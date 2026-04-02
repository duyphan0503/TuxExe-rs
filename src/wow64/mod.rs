//! WoW64 — 32-bit PE32 on 64-bit Linux (thunking and address space management).

pub mod address_space;
pub mod loader;
pub mod teb32;
pub mod thunk;

use crate::exceptions::seh;

/// Configure WoW64 runtime scaffolding for an x86 image mapped in low memory.
pub fn setup_wow64_context(image_base: usize) -> Result<(), String> {
    let image_base32 = u32::try_from(image_base)
        .map_err(|_| format!("image base 0x{image_base:x} exceeds 32-bit range"))?;

    let _reservation = address_space::reserve_low_4gb_on_startup();
    address_space::validate_low_4gb_mapping(image_base, 1)?;

    let teb = teb32::create_teb32(image_base32);
    let _ = teb32::setup_fs_segment_for_teb32(teb.tib.self_ptr);
    seh::set_x86_seh_head(teb.tib.exception_list);
    Ok(())
}
