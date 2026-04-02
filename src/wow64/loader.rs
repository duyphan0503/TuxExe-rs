//! WoW64-specific PE32 loading pipeline.

use std::path::Path;

use crate::pe_loader::imports::{enumerate_imports, ImportTable};
use crate::pe_loader::mapper::{map_pe, MappedImage};
use crate::pe_loader::parser::{Machine, ParsedPe};
use crate::pe_loader::relocations::{apply_relocations, RelocationResult};

use super::address_space::{reserve_low_4gb_on_startup, validate_low_4gb_mapping};

#[derive(Debug)]
pub struct Wow64LoadedImage {
    pub parsed: ParsedPe,
    pub mapped: MappedImage,
    pub reloc_result: RelocationResult,
    pub imports: ImportTable,
}

/// Load and prepare a PE32 image for WoW64 execution.
pub fn load_pe32_image(path: &Path) -> Result<Wow64LoadedImage, String> {
    let parsed = ParsedPe::from_file(path).map_err(|e| e.to_string())?;

    if parsed.machine != Machine::X86 || parsed.is_pe64 {
        return Err(format!(
            "WoW64 loader requires PE32 x86 image, got machine={} pe64={}",
            parsed.machine, parsed.is_pe64
        ));
    }

    let _reservation = reserve_low_4gb_on_startup();

    let mut mapped = map_pe(&parsed).map_err(|e| e.to_string())?;
    validate_low_4gb_mapping(mapped.base_addr(), mapped.size())?;

    let reloc_result = apply_relocations(&parsed, &mut mapped).map_err(|e| e.to_string())?;
    let imports = enumerate_imports(&parsed, &mapped).map_err(|e| e.to_string())?;

    Ok(Wow64LoadedImage { parsed, mapped, reloc_result, imports })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe32() -> Vec<u8> {
        // Similar to parser PE64 synthetic image but with PE32 optional header.
        let mut buf = vec![0u8; 0x400];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // PE signature
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");

        // COFF header
        buf[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // x86
        buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // one section
        buf[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes()); // optional header size for PE32

        let opt = 0x98usize;
        buf[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // image base (u32)
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
        buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
        buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        buf[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // number of rva+sizes

        // Section header at opt + 0xE0
        let sec = opt + 0xE0;
        buf[sec..sec + 5].copy_from_slice(b".text");
        buf[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // virtual size
        buf[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
        buf[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes()); // raw size
        buf[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
        buf[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // RX code

        buf
    }

    #[test]
    fn rejects_non_x86_images_for_wow64_loader() {
        let tmp = tempfile::NamedTempFile::new().expect("tmp file");
        std::fs::write(tmp.path(), crate::pe_loader::parser::tests::minimal_pe64_pub())
            .expect("write pe64");

        let err = load_pe32_image(tmp.path()).expect_err("pe64 should be rejected");
        assert!(err.contains("PE32 x86"));
    }

    #[test]
    fn loads_minimal_pe32_image() {
        let tmp = tempfile::NamedTempFile::new().expect("tmp file");
        std::fs::write(tmp.path(), minimal_pe32()).expect("write pe32");

        let loaded = load_pe32_image(tmp.path()).expect("pe32 should load");
        assert_eq!(loaded.parsed.machine, Machine::X86);
        assert!(!loaded.parsed.is_pe64);
    }
}
