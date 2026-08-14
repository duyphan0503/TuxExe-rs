//! x64 table-based stack unwinding via .pdata RUNTIME_FUNCTION entries.

use std::ffi::c_void;
use std::sync::{OnceLock, RwLock};

use tracing::{debug, info};

use crate::pe_loader::{mapper::MappedImage, parser::ParsedPe};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin_address_rva: u32,
    pub end_address_rva: u32,
    pub unwind_info_rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunctionMatch {
    pub image_base: usize,
    pub function: RuntimeFunction,
}

#[derive(Debug, Clone)]
struct RuntimeFunctionTable {
    image_base: usize,
    entries: Vec<RuntimeFunction>,
}

#[derive(Debug, Clone, Copy)]
struct DynamicRuntimeFunctionTable {
    identifier: u64,
    image_base: usize,
    length: usize,
    callback: usize,
    context: usize,
}

fn runtime_table_cell() -> &'static RwLock<Option<RuntimeFunctionTable>> {
    static TABLE: OnceLock<RwLock<Option<RuntimeFunctionTable>>> = OnceLock::new();
    TABLE.get_or_init(|| RwLock::new(None))
}

fn dynamic_runtime_tables() -> &'static RwLock<Vec<DynamicRuntimeFunctionTable>> {
    static TABLES: OnceLock<RwLock<Vec<DynamicRuntimeFunctionTable>>> = OnceLock::new();
    TABLES.get_or_init(|| RwLock::new(Vec::new()))
}

pub fn install_dynamic_runtime_function_table(
    identifier: u64,
    image_base: usize,
    length: usize,
    callback: usize,
    context: *mut c_void,
) -> bool {
    if identifier == 0 || image_base == 0 || length == 0 || callback == 0 {
        return false;
    }
    let end = match image_base.checked_add(length) {
        Some(end) => end,
        None => return false,
    };
    if end <= image_base {
        return false;
    }
    let mut tables = dynamic_runtime_tables().write().expect("dynamic unwind table poisoned");
    tables.retain(|table| table.identifier != identifier);
    tables.push(DynamicRuntimeFunctionTable {
        identifier,
        image_base,
        length,
        callback,
        context: context as usize,
    });
    info!(
        identifier = format_args!("0x{identifier:x}"),
        image_base = format_args!("0x{image_base:x}"),
        length,
        "Installed dynamic x64 unwind table"
    );
    true
}

pub fn delete_dynamic_runtime_function_table(identifier: usize) -> bool {
    let mut tables = dynamic_runtime_tables().write().expect("dynamic unwind table poisoned");
    let before = tables.len();
    tables.retain(|table| table.identifier != identifier as u64);
    before != tables.len()
}

fn lookup_dynamic_runtime_function(virtual_address: usize) -> Option<RuntimeFunctionMatch> {
    let table = dynamic_runtime_tables()
        .read()
        .expect("dynamic unwind table poisoned")
        .iter()
        .copied()
        .find(|table| {
            table
                .image_base
                .checked_add(table.length)
                .is_some_and(|end| virtual_address >= table.image_base && virtual_address < end)
        })?;
    let callback: extern "win64" fn(u64, *mut c_void) -> *const RuntimeFunction =
        unsafe { std::mem::transmute(table.callback) };
    let entry = callback(virtual_address as u64, table.context as *mut c_void);
    if entry.is_null() {
        return None;
    }
    let function = unsafe { std::ptr::read(entry) };
    (function.begin_address_rva < function.end_address_rva)
        .then_some(RuntimeFunctionMatch { image_base: table.image_base, function })
}

fn parse_runtime_function_entries(bytes: &[u8]) -> Vec<RuntimeFunction> {
    const ENTRY_SIZE: usize = 12;
    let mut entries = Vec::new();

    for chunk in bytes.chunks_exact(ENTRY_SIZE) {
        let begin_address_rva = u32::from_le_bytes(chunk[0..4].try_into().expect("entry begin"));
        let end_address_rva = u32::from_le_bytes(chunk[4..8].try_into().expect("entry end"));
        let unwind_info_rva = u32::from_le_bytes(chunk[8..12].try_into().expect("entry unwind"));

        // Skip empty/sentinel rows.
        if begin_address_rva == 0 && end_address_rva == 0 && unwind_info_rva == 0 {
            continue;
        }
        // Invalid ranges are ignored to keep parser robust.
        if begin_address_rva >= end_address_rva {
            continue;
        }

        entries.push(RuntimeFunction { begin_address_rva, end_address_rva, unwind_info_rva });
    }

    entries.sort_by_key(|e| e.begin_address_rva);
    entries
}

/// Parse `.pdata` runtime function table and publish it for signal-time lookup.
pub fn register_runtime_function_table(pe: &ParsedPe, mapped: &MappedImage) -> Result<(), String> {
    let Some(pdata_section) = pe.sections.iter().find(|s| s.name.eq_ignore_ascii_case(".pdata"))
    else {
        *runtime_table_cell().write().expect("runtime table poisoned") = None;
        info!("No .pdata section found — unwind table disabled");
        return Ok(());
    };

    let rva = pdata_section.virtual_address as usize;
    let size = (pdata_section.virtual_size.max(pdata_section.raw_data_size)) as usize;
    let bytes = mapped.slice_at(rva, size).ok_or_else(|| {
        format!(".pdata range out of mapped image: rva=0x{rva:x} size=0x{size:x}")
    })?;

    let entries = parse_runtime_function_entries(bytes);
    let image_base = mapped.base_addr();
    let table = RuntimeFunctionTable { image_base, entries: entries.clone() };
    *runtime_table_cell().write().expect("runtime table poisoned") = Some(table);

    info!(
        image_base = format_args!("0x{image_base:x}"),
        entries = entries.len(),
        "Registered x64 RUNTIME_FUNCTION unwind table"
    );

    Ok(())
}

/// Lookup a runtime function in the statically parsed main-image table.
///
/// This helper is signal-safe with respect to guest code: it never invokes a
/// callback supplied by a mapped PE module.
pub fn lookup_static_runtime_function(virtual_address: usize) -> Option<RuntimeFunctionMatch> {
    let guard = runtime_table_cell().read().expect("runtime table poisoned");
    let table = guard.as_ref()?;

    let rva = u32::try_from(virtual_address.checked_sub(table.image_base)?).ok()?;
    let idx = table.entries.partition_point(|e| e.begin_address_rva <= rva);
    if idx == 0 {
        return None;
    }
    let candidate = table.entries[idx - 1];
    if rva >= candidate.begin_address_rva && rva < candidate.end_address_rva {
        debug!(
            address = format_args!("0x{virtual_address:x}"),
            begin = format_args!("0x{:x}", candidate.begin_address_rva),
            end = format_args!("0x{:x}", candidate.end_address_rva),
            "Matched runtime function in unwind table"
        );
        Some(RuntimeFunctionMatch { image_base: table.image_base, function: candidate })
    } else {
        None
    }
}

/// Lookup the runtime function containing `virtual_address`.
///
/// Dynamic callback tables are only evaluated from normal guest execution;
/// invoking mapped guest code from a Linux signal handler is not safe.
pub fn lookup_runtime_function(virtual_address: usize) -> Option<RuntimeFunctionMatch> {
    lookup_static_runtime_function(virtual_address)
        .or_else(|| lookup_dynamic_runtime_function(virtual_address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serial_guard;

    #[test]
    fn parses_runtime_function_entries() {
        let bytes = [
            // entry 1: [0x1000, 0x1100), unwind 0x3000
            0x00, 0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x30, 0x00,
            0x00, // entry 2: [0x1200, 0x1300), unwind 0x3010
            0x00, 0x12, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x10, 0x30, 0x00, 0x00,
        ];
        let entries = parse_runtime_function_entries(&bytes);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].begin_address_rva, 0x1000);
        assert_eq!(entries[1].end_address_rva, 0x1300);
    }

    #[test]
    fn lookup_uses_registered_table() {
        let table = RuntimeFunctionTable {
            image_base: 0x1400_0000,
            entries: vec![
                RuntimeFunction {
                    begin_address_rva: 0x1000,
                    end_address_rva: 0x1200,
                    unwind_info_rva: 0x3000,
                },
                RuntimeFunction {
                    begin_address_rva: 0x1200,
                    end_address_rva: 0x1400,
                    unwind_info_rva: 0x3010,
                },
            ],
        };
        *runtime_table_cell().write().expect("runtime table poisoned") = Some(table);

        let hit = lookup_runtime_function(0x1400_1100).expect("match");
        assert_eq!(hit.function.unwind_info_rva, 0x3000);
        assert!(lookup_runtime_function(0x1400_2000).is_none());
    }

    #[test]
    fn lookup_uses_dynamic_callback_outside_static_image() {
        let _guard = serial_guard();
        const IDENTIFIER: u64 = 0x7000_0000_0003;
        const IMAGE_BASE: usize = 0x7000_0000_0000;
        static FUNCTION: RuntimeFunction =
            RuntimeFunction { begin_address_rva: 0, end_address_rva: 0x100, unwind_info_rva: 0x80 };

        extern "win64" fn callback(
            _control_pc: u64,
            _context: *mut c_void,
        ) -> *const RuntimeFunction {
            &FUNCTION
        }

        assert!(install_dynamic_runtime_function_table(
            IDENTIFIER,
            IMAGE_BASE,
            0x1000,
            callback as usize,
            std::ptr::null_mut(),
        ));
        let hit = lookup_runtime_function(IMAGE_BASE + 0x20).expect("dynamic table match");
        assert_eq!(hit.image_base, IMAGE_BASE);
        assert_eq!(hit.function, FUNCTION);
        assert!(delete_dynamic_runtime_function_table(IDENTIFIER as usize));
    }
}
