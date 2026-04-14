//! WoW64 PE32 entry transition scaffolding.

use crate::pe_loader::parser::{Machine, ParsedPe};

use super::thunk::{ThunkArgKind, ThunkDispatcher};

const DEFAULT_STACK_TOP: u32 = 0x7FFE_0000;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86StartupFrame {
    pub return_address: u32,
    pub process_attach_reason: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone)]
pub struct X86EntryTransition {
    pub entry_point_va: u32,
    pub stack_top: u32,
    pub startup_frame: X86StartupFrame,
    pub dispatcher: ThunkDispatcher,
}

fn bootstrap_dispatcher() -> ThunkDispatcher {
    let mut dispatcher = ThunkDispatcher::default();

    // Startup-critical imports frequently exercised by CRT startup.
    dispatcher.register("GetModuleHandleA", &[ThunkArgKind::Pointer]);
    dispatcher.register("GetModuleHandleW", &[ThunkArgKind::Pointer]);
    dispatcher.register("GetProcAddress", &[ThunkArgKind::Handle, ThunkArgKind::Pointer]);
    dispatcher.register("LoadLibraryA", &[ThunkArgKind::Pointer]);
    dispatcher.register("LoadLibraryW", &[ThunkArgKind::Pointer]);
    dispatcher.register(
        "VirtualAlloc",
        &[ThunkArgKind::Pointer, ThunkArgKind::U32, ThunkArgKind::U32, ThunkArgKind::U32],
    );
    dispatcher
        .register("VirtualFree", &[ThunkArgKind::Pointer, ThunkArgKind::U32, ThunkArgKind::U32]);
    dispatcher.register("TlsAlloc", &[]);
    dispatcher.register("TlsGetValue", &[ThunkArgKind::U32]);
    dispatcher.register("TlsSetValue", &[ThunkArgKind::U32, ThunkArgKind::Pointer]);

    dispatcher
}

fn build_startup_frame() -> X86StartupFrame {
    // If the PE32 entrypoint returns unexpectedly, force a controlled trap.
    X86StartupFrame { return_address: 0, process_attach_reason: 1, reserved: 0 }
}

pub fn prepare_entry_transition(
    parsed: &ParsedPe,
    image_base: usize,
) -> Result<X86EntryTransition, String> {
    if parsed.machine != Machine::X86 || parsed.is_pe64 {
        return Err("WoW64 entry transition requires PE32 x86 image".to_string());
    }

    if parsed.entry_point_rva == 0 {
        return Err("PE32 image has no entry point".to_string());
    }

    let entry_point_va = image_base
        .checked_add(parsed.entry_point_rva as usize)
        .ok_or_else(|| "PE32 entry point address overflow".to_string())?;
    let entry_point_va = u32::try_from(entry_point_va)
        .map_err(|_| format!("PE32 entry point 0x{entry_point_va:x} exceeds 32-bit range"))?;

    Ok(X86EntryTransition {
        entry_point_va,
        stack_top: DEFAULT_STACK_TOP,
        startup_frame: build_startup_frame(),
        dispatcher: bootstrap_dispatcher(),
    })
}

pub fn execute_pe32_entry(parsed: &ParsedPe, image_base: usize) -> Result<(), String> {
    let transition = prepare_entry_transition(parsed, image_base)?;

    Err(format!(
        "Native PE32 execution is not available yet: WoW64 x86 entry transition/trampoline dispatcher is incomplete (entry=0x{:x}, stack_top=0x{:x}, registered_thunks={}).",
        transition.entry_point_va,
        transition.stack_top,
        transition.dispatcher.known_api_count()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe32(entry_rva: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];

        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");

        buf[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        buf[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());

        let opt = 0x98usize;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&entry_rva.to_le_bytes());
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());

        let sec = opt + 0xE0;
        buf[sec..sec + 5].copy_from_slice(b".text");
        buf[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes());
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes());
        buf[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        buf
    }

    fn minimal_pe64(entry_rva: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];

        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");

        buf[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        buf[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());

        let opt = 0x98usize;
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&entry_rva.to_le_bytes());
        buf[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        let sec = opt + 0xF0;
        buf[sec..sec + 5].copy_from_slice(b".text");
        buf[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes());
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes());
        buf[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        buf
    }

    #[test]
    fn prepares_transition_for_pe32_image() {
        let parsed = ParsedPe::from_bytes(minimal_pe32(0x1234)).expect("parse pe32");

        let transition =
            prepare_entry_transition(&parsed, 0x0040_0000).expect("transition should prepare");
        assert_eq!(transition.entry_point_va, 0x0040_1234);
        assert_eq!(transition.startup_frame.return_address, 0);
        assert!(transition.dispatcher.known_api_count() >= 8);
    }

    #[test]
    fn rejects_non_pe32_image() {
        let parsed = ParsedPe::from_bytes(minimal_pe64(0x1000)).expect("parse pe64");

        let err = prepare_entry_transition(&parsed, 0x1400_0000)
            .expect_err("PE64 image must be rejected");
        assert!(err.contains("PE32 x86"));
    }
}
