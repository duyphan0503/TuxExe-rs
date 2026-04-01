//! Map PE sections into process memory (mmap + mprotect).
//!
//! Takes a [`ParsedPe`] and produces a [`MappedImage`] with all sections
//! copied into a contiguous anonymous memory region sized to `SizeOfImage`.

use std::ptr;

use tracing::{debug, info, warn};

use super::parser::ParsedPe;
use super::{PeError, PeResult};

/// A PE image mapped into the current process address space.
///
/// The mapping is an anonymous, private region large enough for the entire
/// image (`SizeOfImage`).  Sections are copied at their respective
/// `VirtualAddress` offsets and memory protection is set per section.
pub struct MappedImage {
    /// Base address of the mapping.
    base: *mut u8,
    /// Total size of the mapping in bytes.
    size: usize,
    /// Whether we obtained the preferred image base.
    pub at_preferred: bool,
}

// SAFETY: The mapped region is process-private (MAP_PRIVATE) and we treat
// it as owned by this struct (unmapped on Drop).
unsafe impl Send for MappedImage {}
unsafe impl Sync for MappedImage {}

impl MappedImage {
    /// Base address as a raw pointer.
    pub fn base_ptr(&self) -> *mut u8 {
        self.base
    }

    /// Base address as a `usize`.
    pub fn base_addr(&self) -> usize {
        self.base as usize
    }

    /// Total mapped size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Read a slice from the mapped image at the given RVA.
    ///
    /// Returns `None` if `rva + len` exceeds the mapping.
    pub fn slice_at(&self, rva: usize, len: usize) -> Option<&[u8]> {
        if rva.checked_add(len)? > self.size {
            return None;
        }
        unsafe { Some(std::slice::from_raw_parts(self.base.add(rva), len)) }
    }

    /// Read a mutable slice from the mapped image at the given RVA.
    pub fn slice_at_mut(&mut self, rva: usize, len: usize) -> Option<&mut [u8]> {
        if rva.checked_add(len)? > self.size {
            return None;
        }
        unsafe { Some(std::slice::from_raw_parts_mut(self.base.add(rva), len)) }
    }

    /// Read a `u32` from the mapped image at `rva` (little-endian).
    pub fn read_u32(&self, rva: usize) -> Option<u32> {
        let slice = self.slice_at(rva, 4)?;
        Some(u32::from_le_bytes(slice.try_into().ok()?))
    }

    /// Read a `u64` from the mapped image at `rva` (little-endian).
    pub fn read_u64(&self, rva: usize) -> Option<u64> {
        let slice = self.slice_at(rva, 8)?;
        Some(u64::from_le_bytes(slice.try_into().ok()?))
    }

    /// Write a `u32` to the mapped image at `rva` (little-endian).
    pub fn write_u32(&mut self, rva: usize, val: u32) -> Option<()> {
        let slice = self.slice_at_mut(rva, 4)?;
        slice.copy_from_slice(&val.to_le_bytes());
        Some(())
    }

    /// Write a `u64` to the mapped image at `rva` (little-endian).
    pub fn write_u64(&mut self, rva: usize, val: u64) -> Option<()> {
        let slice = self.slice_at_mut(rva, 8)?;
        slice.copy_from_slice(&val.to_le_bytes());
        Some(())
    }

    /// Write a raw pointer (usize) to the mapped image at `rva`.
    pub fn write_ptr(&mut self, rva: usize, val: usize) -> Option<()> {
        self.write_u64(rva, val as u64)
    }
}

impl Drop for MappedImage {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe {
                libc::munmap(self.base as *mut libc::c_void, self.size);
            }
        }
    }
}

/// Map a parsed PE image into memory.
///
/// 1. `mmap` an anonymous region of `SizeOfImage` bytes.
/// 2. Copy each section's raw data at its `VirtualAddress` offset.
/// 3. Zero-fill any BSS gap (`virtual_size > raw_data_size`).
/// 4. Apply per-section memory protection via `mprotect`.
pub fn map_pe(pe: &ParsedPe) -> PeResult<MappedImage> {
    let total_size = pe.size_of_image as usize;
    if total_size == 0 {
        return Err(PeError::Mapping("SizeOfImage is zero".into()));
    }

    // ── 1. Allocate the mapping ─────────────────────────────────────
    // Try the preferred base first; fall back to any address.
    let (base, at_preferred) = alloc_mapping(pe.image_base as usize, total_size)?;

    info!(
        base = format_args!("0x{:x}", base as usize),
        size = format_args!("0x{total_size:x}"),
        at_preferred,
        "Allocated image mapping"
    );

    // ── 2. Copy PE headers ──────────────────────────────────────────
    // Many programs (and some CRTs) expect the PE headers to be present at the base address.
    let header_size = pe.header_size as usize;
    if header_size > 0 {
        let copy_len = header_size.min(total_size).min(pe.raw.len());
        unsafe {
            ptr::copy_nonoverlapping(pe.raw.as_ptr(), base, copy_len);
        }
    }

    // ── 3. Copy sections ────────────────────────────────────────────
    for sec in &pe.sections {
        let dst_offset = sec.virtual_address as usize;
        let raw_size = sec.raw_data_size as usize;
        let raw_offset = sec.raw_data_offset as usize;
        let virt_size = sec.virtual_size as usize;

        // Skip sections with no virtual size.
        if virt_size == 0 {
            debug!(name = %sec.name, "skipping zero-size section");
            continue;
        }

        // Bounds check on destination.
        if dst_offset + virt_size > total_size {
            return Err(PeError::Mapping(format!(
                "section {} (VA 0x{:x}, vsize 0x{:x}) exceeds SizeOfImage 0x{:x}",
                sec.name, dst_offset, virt_size, total_size
            )));
        }

        // Copy raw data (if any).
        if raw_size > 0 && raw_offset > 0 {
            let copy_len = raw_size.min(virt_size);
            if raw_offset + copy_len > pe.raw.len() {
                return Err(PeError::Mapping(format!(
                    "section {} raw data (offset 0x{:x}, size 0x{:x}) exceeds file size 0x{:x}",
                    sec.name,
                    raw_offset,
                    copy_len,
                    pe.raw.len()
                )));
            }
            unsafe {
                ptr::copy_nonoverlapping(
                    pe.raw.as_ptr().add(raw_offset),
                    base.add(dst_offset),
                    copy_len,
                );
            }
        }

        // Zero-fill any gap (BSS region), already zeroed by MAP_ANONYMOUS
        // but be explicit if we copied raw_size < virt_size.

        debug!(
            name = %sec.name,
            va = format_args!("0x{dst_offset:08x}"),
            copied = raw_size.min(virt_size),
            virt_size,
            perms = %sec.perm_str(),
            "mapped section"
        );
    }

    Ok(MappedImage { base, size: total_size, at_preferred })
}

impl MappedImage {
    /// Apply final memory protections to mapped sections (PROT_READ, etc.).
    /// Call this *after* all relocations and IAT resolution.
    pub fn apply_protections(&mut self, pe: &ParsedPe) -> PeResult<()> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

        // ── 1. Apply protection to headers ──────────────────────────
        let header_size = pe.header_size as usize;
        if header_size > 0 {
            let aligned_header_size = (header_size + page_size - 1) & !(page_size - 1);
            unsafe {
                libc::mprotect(
                    self.base as *mut libc::c_void,
                    aligned_header_size,
                    libc::PROT_READ,
                );
            }
        }

        // ── 2. Apply protection to sections ──────────────────────────
        let alignment = pe.section_alignment.max(1) as usize;
        for sec in &pe.sections {
            let virt_size = sec.virtual_size as usize;
            if virt_size == 0 {
                continue;
            }

            let start = sec.virtual_address as usize;
            let aligned_start = start & !(alignment - 1);
            let aligned_end = (start + virt_size + alignment - 1) & !(alignment - 1);
            let prot_size = aligned_end - aligned_start;

            let prot = section_protection(sec.characteristics);

            let ret = unsafe {
                libc::mprotect(self.base.add(aligned_start) as *mut libc::c_void, prot_size, prot)
            };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                warn!(
                    section = %sec.name,
                    prot = format_args!("0x{prot:x}"),
                    error = %err,
                    "mprotect failed (non-fatal)"
                );
            }
        }
        Ok(())
    }
}

/// Convert PE section characteristics to `mprotect` flags.
fn section_protection(characteristics: u32) -> libc::c_int {
    use super::parser::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};

    let mut prot = libc::PROT_NONE;
    if characteristics & IMAGE_SCN_MEM_READ != 0 {
        prot |= libc::PROT_READ;
    }
    if characteristics & IMAGE_SCN_MEM_WRITE != 0 {
        prot |= libc::PROT_WRITE;
    }
    if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
        prot |= libc::PROT_EXEC;
    }
    // If no flags at all, default to read.
    if prot == libc::PROT_NONE {
        prot = libc::PROT_READ;
    }
    prot
}

/// Try to `mmap` at the preferred address; fall back to any address.
///
/// Returns `(base_pointer, at_preferred_address)`.
fn alloc_mapping(preferred: usize, size: usize) -> PeResult<(*mut u8, bool)> {
    // Page-align the size.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let aligned_size = (size + page_size - 1) & !(page_size - 1);

    // Attempt 1: preferred address.
    if preferred != 0 {
        let addr = unsafe {
            libc::mmap(
                preferred as *mut libc::c_void,
                aligned_size,
                libc::PROT_READ | libc::PROT_WRITE, // RW initially; we tighten per-section later
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr != libc::MAP_FAILED && addr as usize == preferred {
            return Ok((addr as *mut u8, true));
        }
        // Kernel gave us a different address — unmap and retry without hint.
        if addr != libc::MAP_FAILED {
            unsafe {
                libc::munmap(addr, aligned_size);
            }
        }
    }

    // Attempt 2: any address.
    let addr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            aligned_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        return Err(PeError::Mapping(format!("mmap failed: {}", std::io::Error::last_os_error())));
    }

    Ok((addr as *mut u8, false))
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny smoke test: map the minimal PE64 from parser tests.
    #[test]
    fn map_minimal_pe64() {
        let pe_bytes = crate::pe_loader::parser::tests::minimal_pe64_pub();
        let parsed = ParsedPe::from_bytes(pe_bytes).expect("parse");
        let mapped = map_pe(&parsed).expect("map");

        assert!(mapped.base_addr() != 0);
        assert!(mapped.size() >= parsed.size_of_image as usize);

        // The .text section should have been copied; verify first byte
        // (it's all zeros in our synthetic PE, which is fine — we just
        // check the mapping is readable).
        let text_va = parsed.sections[0].virtual_address as usize;
        let slice = mapped.slice_at(text_va, 4).expect("slice");
        assert_eq!(slice.len(), 4);
    }

    #[test]
    fn read_write_u32() {
        let pe_bytes = crate::pe_loader::parser::tests::minimal_pe64_pub();
        let parsed = ParsedPe::from_bytes(pe_bytes).expect("parse");
        let mut mapped = map_pe(&parsed).expect("map");

        let rva = parsed.sections[0].virtual_address as usize;
        mapped.write_u32(rva, 0xDEAD_BEEF).unwrap();
        assert_eq!(mapped.read_u32(rva), Some(0xDEAD_BEEF));
    }

    #[test]
    fn read_write_u64() {
        let pe_bytes = crate::pe_loader::parser::tests::minimal_pe64_pub();
        let parsed = ParsedPe::from_bytes(pe_bytes).expect("parse");
        let mut mapped = map_pe(&parsed).expect("map");

        let rva = parsed.sections[0].virtual_address as usize;
        mapped.write_u64(rva, 0xCAFE_BABE_1234_5678).unwrap();
        assert_eq!(mapped.read_u64(rva), Some(0xCAFE_BABE_1234_5678));
    }

    #[test]
    fn out_of_bounds_returns_none() {
        let pe_bytes = crate::pe_loader::parser::tests::minimal_pe64_pub();
        let parsed = ParsedPe::from_bytes(pe_bytes).expect("parse");
        let mapped = map_pe(&parsed).expect("map");

        // Way past the end.
        assert!(mapped.slice_at(mapped.size() + 100, 1).is_none());
        assert!(mapped.read_u32(mapped.size()).is_none());
    }
}
