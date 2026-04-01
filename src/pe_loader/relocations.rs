//! Process base relocations (.reloc section).
//!
//! When a PE is loaded at an address different from its preferred `ImageBase`,
//! every absolute address embedded in the code/data must be adjusted by the
//! difference (`delta`).  The `.reloc` section contains a table of such
//! fixup entries.

use tracing::{debug, info, warn};

use super::mapper::MappedImage;
use super::parser::ParsedPe;
use super::{PeError, PeResult};

// ── Relocation type constants ───────────────────────────────────────────
/// No fixup (padding entry).
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
/// Add delta to a 32-bit value.
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
/// Add delta to a 64-bit value (PE32+).
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// Result of applying relocations.
#[derive(Debug)]
pub struct RelocationResult {
    /// Number of blocks processed.
    pub blocks_processed: usize,
    /// Number of individual fixups applied.
    pub fixups_applied: usize,
    /// Number of entries skipped (ABSOLUTE / padding).
    pub skipped: usize,
    /// The delta that was applied (actual_base − preferred_base).
    pub delta: i64,
}

/// Apply base relocations to a mapped PE image.
///
/// * `pe`     — The parsed PE metadata (needed for `image_base` and `reloc_dir`).
/// * `mapped` — The mapped image (mutably, since we patch addresses in-place).
///
/// Returns an error if the relocation data is malformed.
/// Returns `Ok` with zero fixups if there are no relocations to apply
/// (either the image was loaded at its preferred address, or there is no
/// `.reloc` directory).
pub fn apply_relocations(pe: &ParsedPe, mapped: &mut MappedImage) -> PeResult<RelocationResult> {
    let preferred = pe.image_base;
    let actual = mapped.base_addr() as u64;
    let delta = actual as i64 - preferred as i64;

    // Nothing to do if loaded at preferred address.
    if delta == 0 {
        info!("Image loaded at preferred base — no relocations needed");
        return Ok(RelocationResult {
            blocks_processed: 0,
            fixups_applied: 0,
            skipped: 0,
            delta: 0,
        });
    }

    // Get the relocation data directory.
    let reloc_dir = match pe.reloc_dir {
        Some(dir) if dir.size > 0 && dir.virtual_address > 0 => dir,
        _ => {
            if pe.is_dynamic_base() {
                warn!(
                    "PE has DYNAMIC_BASE but no .reloc directory — \
                     may crash if image base differs"
                );
            }
            return Ok(RelocationResult {
                blocks_processed: 0,
                fixups_applied: 0,
                skipped: 0,
                delta,
            });
        }
    };

    info!(
        delta = format_args!("{delta:#x}"),
        reloc_rva = format_args!("0x{:x}", reloc_dir.virtual_address),
        reloc_size = reloc_dir.size,
        "Applying base relocations"
    );

    let reloc_data = mapped
        .slice_at(reloc_dir.virtual_address as usize, reloc_dir.size as usize)
        .ok_or_else(|| PeError::Relocation("relocation directory out of bounds".into()))?
        .to_vec(); // owned copy — avoids aliasing `mapped` while we write fixups

    let mut result = RelocationResult { blocks_processed: 0, fixups_applied: 0, skipped: 0, delta };

    // Walk blocks.
    let mut offset = 0usize;
    while offset + 8 <= reloc_data.len() {
        let page_rva = u32::from_le_bytes(
            reloc_data[offset..offset + 4]
                .try_into()
                .map_err(|_| PeError::Relocation("bad block header".into()))?,
        );
        let block_size = u32::from_le_bytes(
            reloc_data[offset + 4..offset + 8]
                .try_into()
                .map_err(|_| PeError::Relocation("bad block header".into()))?,
        ) as usize;

        if block_size < 8 || offset + block_size > reloc_data.len() {
            // End of relocation data (some linkers emit a zero-size sentinel).
            if block_size == 0 {
                break;
            }
            return Err(PeError::Relocation(format!(
                "malformed relocation block at offset 0x{offset:x}: size={block_size}"
            )));
        }

        let num_entries = (block_size - 8) / 2;

        debug!(page_rva = format_args!("0x{page_rva:08x}"), entries = num_entries, "reloc block");

        for i in 0..num_entries {
            let entry_offset = offset + 8 + i * 2;
            let entry = u16::from_le_bytes(
                reloc_data[entry_offset..entry_offset + 2]
                    .try_into()
                    .map_err(|_| PeError::Relocation("truncated entry".into()))?,
            );

            let reloc_type = entry >> 12;
            let reloc_offset = (entry & 0x0FFF) as u32;
            let fixup_rva = (page_rva + reloc_offset) as usize;

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // Padding / no-op.
                    result.skipped += 1;
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    let old = mapped.read_u32(fixup_rva).ok_or_else(|| {
                        PeError::Relocation(format!("HIGHLOW OOB at 0x{fixup_rva:x}"))
                    })?;
                    let new = (old as i64 + delta) as u32;
                    mapped.write_u32(fixup_rva, new).ok_or_else(|| {
                        PeError::Relocation(format!("HIGHLOW write OOB at 0x{fixup_rva:x}"))
                    })?;
                    result.fixups_applied += 1;
                }
                IMAGE_REL_BASED_DIR64 => {
                    let old = mapped.read_u64(fixup_rva).ok_or_else(|| {
                        PeError::Relocation(format!("DIR64 OOB at 0x{fixup_rva:x}"))
                    })?;
                    let new = (old as i64 + delta) as u64;
                    mapped.write_u64(fixup_rva, new).ok_or_else(|| {
                        PeError::Relocation(format!("DIR64 write OOB at 0x{fixup_rva:x}"))
                    })?;
                    result.fixups_applied += 1;
                }
                other => {
                    warn!(
                        reloc_type = other,
                        rva = format_args!("0x{fixup_rva:x}"),
                        "unsupported relocation type — skipping"
                    );
                    result.skipped += 1;
                }
            }
        }

        result.blocks_processed += 1;
        offset += block_size;
    }

    info!(
        blocks = result.blocks_processed,
        fixups = result.fixups_applied,
        skipped = result.skipped,
        delta = format_args!("{delta:#x}"),
        "Relocations complete"
    );

    Ok(result)
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_loader::mapper::map_pe;
    use crate::pe_loader::parser::ParsedPe;

    #[test]
    fn no_relocs_at_preferred_base() {
        // With our minimal PE, at_preferred may or may not be true,
        // but there's no reloc directory at all.
        let pe_bytes = crate::pe_loader::parser::tests::minimal_pe64_pub();
        let parsed = ParsedPe::from_bytes(pe_bytes).unwrap();
        let mut mapped = map_pe(&parsed).unwrap();

        let result = apply_relocations(&parsed, &mut mapped).unwrap();
        // No reloc directory → 0 fixups either way.
        assert_eq!(result.fixups_applied, 0);
        assert_eq!(result.blocks_processed, 0);
    }

    #[test]
    fn synthetic_dir64_relocation() {
        // Build a PE with a .reloc section containing one DIR64 entry.
        let mut buf = crate::pe_loader::parser::tests::minimal_pe64_pub();

        // We'll add a second section: .reloc at VA 0x2000
        // First, bump NumberOfSections to 2.
        buf[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());

        // Add the .reloc section header right after the first section header.
        // Section headers start at 0x188 (opt_hdr_offset 0x98 + opt_hdr_size 0xF0).
        let sec2_off = 0x188 + 40; // second section header
        buf[sec2_off..sec2_off + 6].copy_from_slice(b".reloc");
        // VirtualSize = 16 (one block: 8-byte header + two 2-byte entries)
        buf[sec2_off + 8..sec2_off + 12].copy_from_slice(&16u32.to_le_bytes());
        // VirtualAddress = 0x2000
        buf[sec2_off + 12..sec2_off + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        // SizeOfRawData = 0x200 (one file alignment unit)
        buf[sec2_off + 16..sec2_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        // PointerToRawData = 0x400 (after the first section's raw data at 0x200)
        buf[sec2_off + 20..sec2_off + 24].copy_from_slice(&0x400u32.to_le_bytes());
        // Characteristics = MEM_READ | DISCARDABLE
        let reloc_chars: u32 = 0x4200_0000;
        buf[sec2_off + 36..sec2_off + 40].copy_from_slice(&reloc_chars.to_le_bytes());

        // Extend the buffer so raw data at 0x400 exists.
        buf.resize(0x600, 0);

        // Write relocation block at file offset 0x400:
        // PageRVA = 0x1000 (.text section)
        buf[0x400..0x404].copy_from_slice(&0x1000u32.to_le_bytes());
        // BlockSize = 12 (header=8 + 2 entries*2)
        buf[0x404..0x408].copy_from_slice(&12u32.to_le_bytes());
        // Entry 0: type=DIR64 (10 << 12), offset=0x000
        let entry0: u16 = IMAGE_REL_BASED_DIR64 << 12;
        buf[0x408..0x40A].copy_from_slice(&entry0.to_le_bytes());
        // Entry 1: ABSOLUTE (padding)
        buf[0x40A..0x40C].copy_from_slice(&0u16.to_le_bytes());

        // Set the data directory #5 (base reloc).
        // Data dirs start at optional_header + 112 = 0x98 + 112 = 0x108.
        // Index 5 = offset 0x108 + 5*8 = 0x130.
        let dd5_offset = 0x108 + 5 * 8;
        buf[dd5_offset..dd5_offset + 4].copy_from_slice(&0x2000u32.to_le_bytes()); // RVA
        buf[dd5_offset + 4..dd5_offset + 8].copy_from_slice(&12u32.to_le_bytes()); // Size

        // Also update SizeOfImage to include the new section.
        buf[0xD0..0xD4].copy_from_slice(&0x4000u32.to_le_bytes());

        // Plant a known u64 value at RVA 0x1000 in the first section's raw data.
        // Raw data for .text is at file offset 0x200.
        let test_addr: u64 = 0x0040_1000; // preferred address
        buf[0x200..0x208].copy_from_slice(&test_addr.to_le_bytes());

        // Parse and map.
        let parsed = ParsedPe::from_bytes(buf).unwrap();
        assert!(parsed.reloc_dir.is_some());
        let mut mapped = map_pe(&parsed).unwrap();

        // Write the test value at mapped RVA 0x1000 (it was copied from raw data).
        // Verify it's there.
        let before = mapped.read_u64(0x1000).unwrap();
        assert_eq!(before, test_addr);

        // Apply relocations.
        let result = apply_relocations(&parsed, &mut mapped).unwrap();

        if result.delta != 0 {
            assert!(result.fixups_applied >= 1, "should apply at least one DIR64 fixup");
            let after = mapped.read_u64(0x1000).unwrap();
            let expected = (test_addr as i64 + result.delta) as u64;
            assert_eq!(after, expected, "DIR64 fixup should adjust the value by delta");
        }
    }
}
