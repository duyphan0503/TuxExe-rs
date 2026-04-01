//! Import Address Table (IAT) resolution.
//!
//! Phase 1 (this file): parse the Import Directory Table and enumerate every
//! DLL / function the PE requires.  Resolution is deferred to Phase 2.

use std::fmt;

use tracing::{debug, info};

use super::mapper::MappedImage;
use super::parser::ParsedPe;
use super::{PeError, PeResult};

/// One imported function.
#[derive(Debug, Clone)]
pub struct ImportEntry {
    /// Name of the DLL (e.g. "KERNEL32.dll").
    pub dll: String,
    /// Function name or ordinal.
    pub import: ImportKind,
    /// RVA of the IAT slot (where the resolved address must be written).
    pub iat_rva: usize,
    /// Whether this import was discovered from delay-import descriptors.
    pub delayed: bool,
}

/// Whether a function is imported by name or ordinal.
#[derive(Debug, Clone)]
pub enum ImportKind {
    /// Imported by name (normal case).
    ByName { hint: u16, name: String },
    /// Imported by ordinal number.
    ByOrdinal(u16),
}

impl fmt::Display for ImportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportKind::ByName { name, hint } => write!(f, "{name} (hint {hint})"),
            ImportKind::ByOrdinal(ord) => write!(f, "ordinal #{ord}"),
        }
    }
}

/// Summary of all imports enumerated from a PE.
#[derive(Debug)]
pub struct ImportTable {
    /// Grouped by DLL → functions.
    pub entries: Vec<ImportEntry>,
    /// Unique DLL names referenced.
    pub dlls: Vec<String>,
}

impl ImportTable {
    /// Iterate over imports for a specific DLL (case-insensitive).
    pub fn for_dll(&self, dll: &str) -> impl Iterator<Item = &ImportEntry> {
        let dll_lower = dll.to_ascii_lowercase();
        self.entries.iter().filter(move |e| e.dll.to_ascii_lowercase() == dll_lower)
    }

    /// Total number of imported functions.
    pub fn total_imports(&self) -> usize {
        self.entries.len()
    }
}

/// Enumerate all imports from a mapped PE image (Phase 1: discovery only).
///
/// Walks the IMAGE_IMPORT_DESCRIPTOR array in the import data directory,
/// reads the Import Lookup Table (ILT) / Import Name Table (INT) to
/// discover every DLL and function required.
///
/// Does **not** resolve or patch any IAT entries — that's Phase 2.
pub fn enumerate_imports(pe: &ParsedPe, mapped: &MappedImage) -> PeResult<ImportTable> {
    let import_dir = match pe.import_dir {
        Some(dir) if dir.size > 0 && dir.virtual_address > 0 => dir,
        _ => {
            info!("No import directory — statically linked or no imports");
            return Ok(ImportTable { entries: Vec::new(), dlls: Vec::new() });
        }
    };

    info!(
        import_rva = format_args!("0x{:x}", import_dir.virtual_address),
        import_size = import_dir.size,
        "Enumerating PE imports"
    );

    let mut entries = Vec::new();
    let mut dlls = Vec::new();

    // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes.
    // The array is terminated by an all-zero entry.
    let desc_size = 20usize;
    let mut desc_rva = import_dir.virtual_address as usize;

    loop {
        // Read the 5 × u32 fields.
        let ilt_rva = mapped
            .read_u32(desc_rva)
            .ok_or_else(|| PeError::Parse("import descriptor OriginalFirstThunk OOB".into()))?
            as usize;
        let _timestamp = mapped.read_u32(desc_rva + 4).unwrap_or(0);
        let _forwarder = mapped.read_u32(desc_rva + 8).unwrap_or(0);
        let name_rva = mapped
            .read_u32(desc_rva + 12)
            .ok_or_else(|| PeError::Parse("import descriptor Name RVA OOB".into()))?
            as usize;
        let iat_rva_start = mapped
            .read_u32(desc_rva + 16)
            .ok_or_else(|| PeError::Parse("import descriptor FirstThunk OOB".into()))?
            as usize;

        // Terminator: all fields zero.
        if ilt_rva == 0 && name_rva == 0 {
            break;
        }

        // Read the DLL name (null-terminated ASCII at name_rva).
        let dll_name = read_ascii_string(mapped, name_rva)
            .ok_or_else(|| PeError::Parse(format!("cannot read DLL name at RVA 0x{name_rva:x}")))?;

        if !dlls.iter().any(|d: &String| d.eq_ignore_ascii_case(&dll_name)) {
            dlls.push(dll_name.clone());
        }

        debug!(dll = %dll_name, ilt_rva = format_args!("0x{ilt_rva:x}"), "import descriptor");

        // Walk the ILT (or IAT if ILT RVA is 0 — bound imports).
        let thunk_table_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva_start };

        let thunk_size = if pe.is_pe64 { 8usize } else { 4usize };
        let ordinal_flag: u64 = if pe.is_pe64 { 0x8000_0000_0000_0000 } else { 0x8000_0000 };

        let mut idx = 0usize;
        loop {
            let thunk_rva = thunk_table_rva + idx * thunk_size;
            let thunk_val = if pe.is_pe64 {
                mapped.read_u64(thunk_rva).unwrap_or(0)
            } else {
                mapped.read_u32(thunk_rva).unwrap_or(0) as u64
            };

            // Terminator.
            if thunk_val == 0 {
                break;
            }

            let iat_slot_rva = iat_rva_start + idx * thunk_size;

            let import = if thunk_val & ordinal_flag != 0 {
                // Import by ordinal.
                let ord = (thunk_val & 0xFFFF) as u16;
                ImportKind::ByOrdinal(ord)
            } else {
                // Import by name — thunk_val is an RVA to a Hint/Name entry.
                let hint_name_rva = (thunk_val & 0x7FFF_FFFF) as usize;
                let hint = mapped.read_u32(hint_name_rva).unwrap_or(0) as u16;
                let func_name = read_ascii_string(mapped, hint_name_rva + 2).unwrap_or_default();
                ImportKind::ByName { hint, name: func_name }
            };

            debug!(
                dll = %dll_name,
                import = %import,
                iat_rva = format_args!("0x{iat_slot_rva:x}"),
                "  import"
            );

            entries.push(ImportEntry {
                dll: dll_name.clone(),
                import,
                iat_rva: iat_slot_rva,
                delayed: false,
            });

            idx += 1;
        }

        desc_rva += desc_size;
    }

    info!(dll_count = dlls.len(), import_count = entries.len(), "Import enumeration complete");
    for dll in &dlls {
        let count = entries.iter().filter(|e| e.dll.eq_ignore_ascii_case(dll)).count();
        info!(dll = %dll, functions = count, "  required DLL");
    }

    Ok(ImportTable { entries, dlls })
}

/// Enumerate delay-loaded imports from IMAGE_DELAY_IMPORT_DESCRIPTOR.
pub fn enumerate_delay_imports(pe: &ParsedPe, mapped: &MappedImage) -> PeResult<ImportTable> {
    let delay_dir = match pe.delay_import_dir {
        Some(dir) if dir.size > 0 && dir.virtual_address > 0 => dir,
        _ => {
            info!("No delay import directory");
            return Ok(ImportTable { entries: Vec::new(), dlls: Vec::new() });
        }
    };

    info!(
        delay_import_rva = format_args!("0x{:x}", delay_dir.virtual_address),
        delay_import_size = delay_dir.size,
        "Enumerating PE delay imports"
    );

    let mut entries = Vec::new();
    let mut dlls = Vec::new();

    // IMAGE_DELAY_IMPORT_DESCRIPTOR (PE32/PE32+) is 8 DWORDs = 32 bytes.
    let desc_size = 32usize;
    let mut desc_rva = delay_dir.virtual_address as usize;

    loop {
        let gr_attrs = mapped.read_u32(desc_rva).unwrap_or(0);
        let name_rva_or_va = mapped.read_u32(desc_rva + 4).unwrap_or(0) as usize;
        let _hmod_rva_or_va = mapped.read_u32(desc_rva + 8).unwrap_or(0);
        let iat_rva_or_va = mapped.read_u32(desc_rva + 12).unwrap_or(0) as usize;
        let int_rva_or_va = mapped.read_u32(desc_rva + 16).unwrap_or(0) as usize;
        let _bound_iat = mapped.read_u32(desc_rva + 20).unwrap_or(0);
        let _unload_iat = mapped.read_u32(desc_rva + 24).unwrap_or(0);
        let _timestamp = mapped.read_u32(desc_rva + 28).unwrap_or(0);

        // Terminator descriptor is all zeros.
        if gr_attrs == 0 && name_rva_or_va == 0 && iat_rva_or_va == 0 && int_rva_or_va == 0 {
            break;
        }

        // If attrs bit0 is 1, fields are VAs. We currently support RVA mode only.
        if gr_attrs & 1 != 0 {
            debug!(
                descriptor_rva = format_args!("0x{desc_rva:x}"),
                "Skipping delay import descriptor using VA form (unsupported)"
            );
            desc_rva += desc_size;
            continue;
        }

        let dll_name = match read_ascii_string(mapped, name_rva_or_va) {
            Some(name) => name,
            None => {
                desc_rva += desc_size;
                continue;
            }
        };

        if !dlls.iter().any(|d: &String| d.eq_ignore_ascii_case(&dll_name)) {
            dlls.push(dll_name.clone());
        }

        let thunk_table_rva = if int_rva_or_va != 0 { int_rva_or_va } else { iat_rva_or_va };
        let thunk_size = if pe.is_pe64 { 8usize } else { 4usize };
        let ordinal_flag: u64 = if pe.is_pe64 { 0x8000_0000_0000_0000 } else { 0x8000_0000 };

        let mut idx = 0usize;
        loop {
            let thunk_rva = thunk_table_rva + idx * thunk_size;
            let thunk_val = if pe.is_pe64 {
                mapped.read_u64(thunk_rva).unwrap_or(0)
            } else {
                mapped.read_u32(thunk_rva).unwrap_or(0) as u64
            };
            if thunk_val == 0 {
                break;
            }

            let iat_slot_rva = iat_rva_or_va + idx * thunk_size;
            let import = if thunk_val & ordinal_flag != 0 {
                ImportKind::ByOrdinal((thunk_val & 0xFFFF) as u16)
            } else {
                let hint_name_rva = (thunk_val & 0x7FFF_FFFF) as usize;
                let hint = mapped.read_u32(hint_name_rva).unwrap_or(0) as u16;
                let func_name = read_ascii_string(mapped, hint_name_rva + 2).unwrap_or_default();
                ImportKind::ByName { hint, name: func_name }
            };

            entries.push(ImportEntry {
                dll: dll_name.clone(),
                import,
                iat_rva: iat_slot_rva,
                delayed: true,
            });
            idx += 1;
        }

        desc_rva += desc_size;
    }

    info!(
        dll_count = dlls.len(),
        import_count = entries.len(),
        "Delay import enumeration complete"
    );

    Ok(ImportTable { entries, dlls })
}

/// Resolve all enumerated imports and write their addresses into the mapped IAT.
///
/// Looks up each function in the `dll_manager` dispatch table. If found, writes
/// the resulting function pointer into the IAT. Unresolved imports are currently
/// skipped (logged as warnings) allowing execution to proceed until such a function
/// is called.
pub fn resolve_imports(
    mapped: &mut MappedImage,
    pe: &ParsedPe,
    import_table: &ImportTable,
) -> PeResult<()> {
    info!("Resolving {} imports", import_table.entries.len());

    let _ptr_size = if pe.is_pe64 { 8 } else { 4 };

    for entry in &import_table.entries {
        let func_name = match &entry.import {
            ImportKind::ByName { name, .. } => name.clone(),
            ImportKind::ByOrdinal(ord) => format!("ordinal#{}", ord),
        };

        let ptr = match crate::dll_manager::load_library(&entry.dll) {
            Ok(handle) => match &entry.import {
                ImportKind::ByName { name, .. } => crate::dll_manager::resolve_export(handle, name),
                ImportKind::ByOrdinal(_) => None,
            },
            Err(_) => None,
        };

        let Some(ptr) = ptr else {
            tracing::warn!(
                dll = %entry.dll,
                func = %func_name,
                delayed = entry.delayed,
                "Unresolved import — will crash if called!"
            );
            continue;
        };

        debug!(
            dll = %entry.dll,
            func = %func_name,
            ptr = format_args!("0x{:x}", ptr),
            "Resolved import"
        );

        if pe.is_pe64 {
            mapped.write_u64(entry.iat_rva, ptr as u64).ok_or_else(|| {
                PeError::Mapping(format!("Failed to write IAT entry at 0x{:x}", entry.iat_rva))
            })?;
        } else {
            mapped.write_u32(entry.iat_rva, ptr as u32).ok_or_else(|| {
                PeError::Mapping(format!("Failed to write IAT entry at 0x{:x}", entry.iat_rva))
            })?;
        }
    }

    Ok(())
}

/// Read a null-terminated ASCII string from the mapped image.
fn read_ascii_string(mapped: &MappedImage, rva: usize) -> Option<String> {
    let mut s = String::new();
    let mut offset = rva;
    loop {
        let byte_slice = mapped.slice_at(offset, 1)?;
        let b = byte_slice[0];
        if b == 0 {
            break;
        }
        s.push(b as char);
        offset += 1;
        // Safety limit — DLL / function names shouldn't exceed 512 chars.
        if s.len() > 512 {
            break;
        }
    }
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_loader::mapper::map_pe;
    use crate::pe_loader::parser::ParsedPe;

    #[test]
    fn no_imports_returns_empty() {
        let pe_bytes = crate::pe_loader::parser::tests::minimal_pe64_pub();
        let parsed = ParsedPe::from_bytes(pe_bytes).unwrap();
        let mapped = map_pe(&parsed).unwrap();

        let imports = enumerate_imports(&parsed, &mapped).unwrap();
        assert_eq!(imports.total_imports(), 0);
        assert!(imports.dlls.is_empty());
    }

    #[test]
    fn import_kind_display() {
        let by_name = ImportKind::ByName { hint: 42, name: "ExitProcess".into() };
        assert!(by_name.to_string().contains("ExitProcess"));
        assert!(by_name.to_string().contains("42"));

        let by_ord = ImportKind::ByOrdinal(100);
        assert!(by_ord.to_string().contains("100"));
    }

    #[test]
    fn for_dll_filter() {
        let table = ImportTable {
            entries: vec![
                ImportEntry {
                    dll: "KERNEL32.dll".into(),
                    import: ImportKind::ByName { hint: 0, name: "ExitProcess".into() },
                    iat_rva: 0x1000,
                    delayed: false,
                },
                ImportEntry {
                    dll: "msvcrt.dll".into(),
                    import: ImportKind::ByName { hint: 0, name: "printf".into() },
                    iat_rva: 0x1008,
                    delayed: false,
                },
                ImportEntry {
                    dll: "KERNEL32.dll".into(),
                    import: ImportKind::ByName { hint: 0, name: "GetStdHandle".into() },
                    iat_rva: 0x1010,
                    delayed: false,
                },
            ],
            dlls: vec!["KERNEL32.dll".into(), "msvcrt.dll".into()],
        };

        let k32: Vec<_> = table.for_dll("kernel32.dll").collect();
        assert_eq!(k32.len(), 2);

        let msvcrt: Vec<_> = table.for_dll("MSVCRT.DLL").collect();
        assert_eq!(msvcrt.len(), 1);
    }

    #[test]
    fn no_delay_imports_returns_empty() {
        let pe_bytes = crate::pe_loader::parser::tests::minimal_pe64_pub();
        let parsed = ParsedPe::from_bytes(pe_bytes).unwrap();
        let mapped = map_pe(&parsed).unwrap();

        let imports = enumerate_delay_imports(&parsed, &mapped).unwrap();
        assert_eq!(imports.total_imports(), 0);
        assert!(imports.dlls.is_empty());
    }
}
