//! PE header parsing via `goblin`.
//!
//! Reads a PE file from a byte slice and extracts all the metadata needed by
//! the mapper, relocation engine, and import resolver.

use std::fmt;
use std::fs;
use std::path::Path;

use goblin::pe::header::{COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use goblin::pe::section_table::SectionTable;
use goblin::pe::PE;
use tracing::{debug, info};

use super::{PeError, PeResult};

// ── Section characteristic flag constants ───────────────────────────────
/// Section contains executable code.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// Section is readable.
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// Section is writable.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// Section contains uninitialised data (BSS).
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;

// ── Parsed types ────────────────────────────────────────────────────────

/// Machine architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    X86,
    X64,
    Unknown(u16),
}

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Machine::X86 => write!(f, "x86 (PE32)"),
            Machine::X64 => write!(f, "x86-64 (PE32+)"),
            Machine::Unknown(v) => write!(f, "unknown(0x{v:04x})"),
        }
    }
}

/// Describes one PE section with all the information the mapper needs.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    /// Section name (UTF-8, trimmed of NUL padding).
    pub name: String,
    /// Relative virtual address (offset from image base).
    pub virtual_address: u32,
    /// Size in memory (may be larger than raw data = BSS).
    pub virtual_size: u32,
    /// Offset of raw data in the file.
    pub raw_data_offset: u32,
    /// Size of raw data on disk.
    pub raw_data_size: u32,
    /// Raw section characteristics bitfield.
    pub characteristics: u32,
}

impl SectionInfo {
    /// Whether the section is executable.
    pub fn is_exec(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
    /// Whether the section is writable.
    pub fn is_write(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }
    /// Whether the section is readable.
    pub fn is_read(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }
    /// Whether the section is BSS (uninitialised data).
    pub fn is_bss(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
    }

    /// Returns a concise permission string like `RWX`, `R-X`, `RW-`.
    pub fn perm_str(&self) -> String {
        let r = if self.is_read() { 'R' } else { '-' };
        let w = if self.is_write() { 'W' } else { '-' };
        let x = if self.is_exec() { 'X' } else { '-' };
        format!("{r}{w}{x}")
    }

    /// Build from a `goblin` section table entry.
    fn from_goblin(sec: &SectionTable) -> Self {
        let name = String::from_utf8_lossy(&sec.name)
            .trim_end_matches('\0')
            .to_string();

        Self {
            name,
            virtual_address: sec.virtual_address,
            virtual_size: sec.virtual_size,
            raw_data_offset: sec.pointer_to_raw_data,
            raw_data_size: sec.size_of_raw_data,
            characteristics: sec.characteristics,
        }
    }
}

/// Represents a data directory entry (RVA + size).
#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// A fully parsed PE file (owned).
///
/// Holds the raw bytes and every piece of metadata the downstream stages need.
pub struct ParsedPe {
    /// Raw file bytes.
    pub raw: Vec<u8>,
    /// Target machine.
    pub machine: Machine,
    /// Whether this is a PE32+ (64-bit) image.
    pub is_pe64: bool,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Preferred image base from the optional header.
    pub image_base: u64,
    /// RVA of the entry point.
    pub entry_point_rva: u32,
    /// Total virtual size of the loaded image.
    pub size_of_image: u32,
    /// Section alignment in memory.
    pub section_alignment: u32,
    /// File alignment on disk.
    pub file_alignment: u32,
    /// Parsed sections.
    pub sections: Vec<SectionInfo>,
    /// Base relocation data directory.
    pub reloc_dir: Option<DataDirectory>,
    /// Import data directory.
    pub import_dir: Option<DataDirectory>,
    /// DLL characteristics (e.g. DYNAMIC_BASE for ASLR).
    pub dll_characteristics: u16,
}

impl fmt::Debug for ParsedPe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedPe")
            .field("machine", &self.machine)
            .field("is_pe64", &self.is_pe64)
            .field("image_base", &format_args!("0x{:x}", self.image_base))
            .field(
                "entry_point_rva",
                &format_args!("0x{:x}", self.entry_point_rva),
            )
            .field(
                "size_of_image",
                &format_args!("0x{:x}", self.size_of_image),
            )
            .field("sections", &self.sections.len())
            .finish()
    }
}

// ── Constants for data-directory indices ─────────────────────────────────

impl ParsedPe {
    /// Parse a PE file from raw bytes.
    pub fn from_bytes(raw: Vec<u8>) -> PeResult<Self> {
        // ── 1. DOS header sanity ────────────────────────────────────
        if raw.len() < 64 {
            return Err(PeError::InvalidPe("file too small for DOS header".into()));
        }
        if raw[0] != b'M' || raw[1] != b'Z' {
            return Err(PeError::InvalidPe(
                "missing MZ magic (not a PE file)".into(),
            ));
        }

        // ── 2. Parse with goblin ────────────────────────────────────
        let pe = PE::parse(&raw).map_err(|e| PeError::Parse(format!("{e}")))?;

        // ── 3. Machine type ─────────────────────────────────────────
        let machine_raw = pe.header.coff_header.machine;
        let machine = match machine_raw {
            COFF_MACHINE_X86 => Machine::X86,
            COFF_MACHINE_X86_64 => Machine::X64,
            other => Machine::Unknown(other),
        };

        // ── 4. Optional header ──────────────────────────────────────
        let opt = pe
            .header
            .optional_header
            .ok_or_else(|| PeError::InvalidPe("missing optional header".into()))?;

        let is_pe64 = opt.standard_fields.magic == goblin::pe::optional_header::MAGIC_64;
        let image_base = opt.windows_fields.image_base;
        let entry_point_rva = opt.standard_fields.address_of_entry_point as u32;
        let size_of_image = opt.windows_fields.size_of_image;
        let section_alignment = opt.windows_fields.section_alignment;
        let file_alignment = opt.windows_fields.file_alignment;
        let dll_characteristics = opt.windows_fields.dll_characteristics;
        let number_of_sections = pe.header.coff_header.number_of_sections;

        // ── 5. Data directories ─────────────────────────────────────
        let data_dirs = &opt.data_directories;

        let import_dir = data_dirs.get_import_table().map(|d| DataDirectory {
            virtual_address: d.virtual_address,
            size: d.size,
        });

        let reloc_dir = data_dirs.get_base_relocation_table().map(|d| DataDirectory {
            virtual_address: d.virtual_address,
            size: d.size,
        });

        // ── 6. Sections ─────────────────────────────────────────────
        let sections: Vec<SectionInfo> = pe.sections.iter().map(SectionInfo::from_goblin).collect();

        info!(
            machine = %machine,
            is_pe64,
            image_base = format_args!("0x{image_base:x}"),
            entry_point = format_args!("0x{entry_point_rva:x}"),
            size_of_image = format_args!("0x{size_of_image:x}"),
            num_sections = sections.len(),
            "Parsed PE headers"
        );

        for sec in &sections {
            debug!(
                name = %sec.name,
                va = format_args!("0x{:08x}", sec.virtual_address),
                vsize = format_args!("0x{:x}", sec.virtual_size),
                raw_offset = format_args!("0x{:x}", sec.raw_data_offset),
                raw_size = format_args!("0x{:x}", sec.raw_data_size),
                perms = %sec.perm_str(),
                "  section"
            );
        }

        Ok(Self {
            raw,
            machine,
            is_pe64,
            number_of_sections,
            image_base,
            entry_point_rva,
            size_of_image,
            section_alignment,
            file_alignment,
            sections,
            reloc_dir,
            import_dir,
            dll_characteristics,
        })
    }

    /// Parse a PE file from disk.
    pub fn from_file(path: &Path) -> PeResult<Self> {
        let raw = fs::read(path)?;
        info!(path = %path.display(), size = raw.len(), "Read PE file");
        Self::from_bytes(raw)
    }

    /// Absolute virtual address of the entry point (based on preferred image base).
    pub fn preferred_entry_point(&self) -> u64 {
        self.image_base + self.entry_point_rva as u64
    }

    /// Whether dynamic-base (ASLR) is set.
    pub fn is_dynamic_base(&self) -> bool {
        // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
        self.dll_characteristics & 0x0040 != 0
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Helper: build a minimal valid PE64 binary (no sections, no code).
    /// Public within the crate so other test modules can reuse it.
    pub fn minimal_pe64_pub() -> Vec<u8> {
        minimal_pe64()
    }

    fn minimal_pe64() -> Vec<u8> {
        // Allocate enough space: headers need to fit within 0x200.
        // Layout:
        //   0x00:  DOS header (with e_lfanew=0x80)
        //   0x80:  PE signature (4 bytes)
        //   0x84:  COFF header (20 bytes)
        //   0x98:  Optional header (240 bytes = 24 std + 88 win + 128 dirs)
        //   0x188: Section headers (40 bytes each)
        //   0x200: Raw section data
        let mut buf = vec![0u8; 0x200 + 0x100]; // headers + one section of raw data

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew → PE sig at 0x80
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // PE signature at 0x80
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");

        // COFF header (20 bytes) at 0x84
        // Machine = AMD64 (0x8664)
        buf[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        // NumberOfSections = 1
        buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        // SizeOfOptionalHeader = 240 (0xF0): 24 std + 88 win + 16*8 dirs
        buf[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());

        // Optional header at 0x98
        // Magic = PE32+ (0x020B)
        buf[0x98..0x9A].copy_from_slice(&0x020Bu16.to_le_bytes());
        // AddressOfEntryPoint at offset 0x98 + 16 = 0xA8
        buf[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes());
        // ImageBase at offset 0x98 + 24 = 0xB0 (8 bytes for PE32+)
        buf[0xB0..0xB8].copy_from_slice(&0x0040_0000u64.to_le_bytes());
        // SectionAlignment at offset 0x98 + 32 = 0xB8
        buf[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes());
        // FileAlignment at offset 0x98 + 36 = 0xBC
        buf[0xBC..0xC0].copy_from_slice(&0x0200u32.to_le_bytes());
        // SizeOfImage at offset 0x98 + 56 = 0xD0
        buf[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes());
        // SizeOfHeaders at offset 0x98 + 60 = 0xD4
        buf[0xD4..0xD8].copy_from_slice(&0x0200u32.to_le_bytes());
        // NumberOfRvaAndSizes at offset 0x98 + 108 = 0x104
        buf[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());

        // Data directories (16 * 8 = 128 bytes at 0x108..0x188) — all zero = no dirs.
        // Already zero from initialization.

        // Section header at 0x98 + 240 = 0x188 (each section header = 40 bytes)
        let sec_off = 0x188;
        // Name = ".text\0\0\0"
        buf[sec_off..sec_off + 5].copy_from_slice(b".text");
        // VirtualSize
        buf[sec_off + 8..sec_off + 12].copy_from_slice(&0x100u32.to_le_bytes());
        // VirtualAddress
        buf[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        // SizeOfRawData
        buf[sec_off + 16..sec_off + 20].copy_from_slice(&0x100u32.to_le_bytes());
        // PointerToRawData
        buf[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes());
        // Characteristics = EXEC | READ | WRITE
        buf[sec_off + 36..sec_off + 40]
            .copy_from_slice(&(IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE).to_le_bytes());

        buf
    }

    #[test]
    fn parse_minimal_pe64() {
        let pe = ParsedPe::from_bytes(minimal_pe64()).expect("should parse");
        assert_eq!(pe.machine, Machine::X64);
        assert!(pe.is_pe64);
        assert_eq!(pe.image_base, 0x0040_0000);
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert_eq!(pe.size_of_image, 0x3000);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name, ".text");
        assert!(pe.sections[0].is_exec());
        assert!(pe.sections[0].is_read());
        assert!(pe.sections[0].is_write());
    }

    #[test]
    fn reject_short_file() {
        let data = vec![0u8; 32]; // too small
        assert!(ParsedPe::from_bytes(data).is_err());
    }

    #[test]
    fn reject_non_mz() {
        let mut data = minimal_pe64();
        data[0] = b'E';
        data[1] = b'L';
        let err = ParsedPe::from_bytes(data).unwrap_err();
        assert!(err.to_string().contains("MZ"));
    }

    #[test]
    fn preferred_entry_point_calculation() {
        let pe = ParsedPe::from_bytes(minimal_pe64()).unwrap();
        assert_eq!(pe.preferred_entry_point(), 0x0040_0000 + 0x1000);
    }

    #[test]
    fn section_perm_string() {
        let pe = ParsedPe::from_bytes(minimal_pe64()).unwrap();
        assert_eq!(pe.sections[0].perm_str(), "RWX");
    }

    #[test]
    fn machine_display() {
        assert_eq!(Machine::X64.to_string(), "x86-64 (PE32+)");
        assert_eq!(Machine::X86.to_string(), "x86 (PE32)");
        assert_eq!(Machine::Unknown(0x1234).to_string(), "unknown(0x1234)");
    }
}
