//! 32-bit TEB setup and FS segment bootstrap for WoW64 threads.

use std::cell::Cell;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NtTib32 {
    pub exception_list: u32,
    pub stack_base: u32,
    pub stack_limit: u32,
    pub sub_system_tib: u32,
    pub fiber_data: u32,
    pub arbitrary_user_pointer: u32,
    pub self_ptr: u32,
}

impl Default for NtTib32 {
    fn default() -> Self {
        Self {
            exception_list: 0xFFFF_FFFF,
            stack_base: 0,
            stack_limit: 0,
            sub_system_tib: 0,
            fiber_data: 0,
            arbitrary_user_pointer: 0,
            self_ptr: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Teb32 {
    pub tib: NtTib32,
    pub process_environment_block: u32,
    pub last_error_value: u32,
    pub tls_slots: [u32; 64],
}

impl Default for Teb32 {
    fn default() -> Self {
        Self {
            tib: NtTib32::default(),
            process_environment_block: 0,
            last_error_value: 0,
            tls_slots: [0; 64],
        }
    }
}

thread_local! {
    static CURRENT_TEB32: Cell<u32> = const { Cell::new(0) };
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct UserDesc32 {
    entry_number: u32,
    base_addr: u32,
    limit: u32,
    seg_32bit: u32,
    contents: u32,
    read_exec_only: u32,
    limit_in_pages: u32,
    seg_not_present: u32,
    useable: u32,
    #[cfg(target_arch = "x86_64")]
    lm: u32,
}

fn build_user_desc(teb_base: u32) -> UserDesc32 {
    UserDesc32 {
        entry_number: u32::MAX,
        base_addr: teb_base,
        limit: 0xFFFFF,
        seg_32bit: 1,
        contents: 0,
        read_exec_only: 0,
        limit_in_pages: 1,
        seg_not_present: 0,
        useable: 1,
        #[cfg(target_arch = "x86_64")]
        lm: 0,
    }
}

/// Best-effort FS setup for 32-bit thread context via `modify_ldt`.
pub fn setup_fs_segment_for_teb32(teb_base: u32) -> Result<(), String> {
    #[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
    {
        let mut desc = build_user_desc(teb_base);
        let ret = unsafe {
            libc::syscall(
                libc::SYS_modify_ldt,
                1,
                &mut desc as *mut UserDesc32,
                std::mem::size_of::<UserDesc32>(),
            )
        };

        if ret < 0 {
            return Err(format!("modify_ldt failed: {}", std::io::Error::last_os_error()));
        }

        CURRENT_TEB32.with(|slot| slot.set(teb_base));
        Ok(())
    }

    #[cfg(not(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64"))))]
    {
        let _ = teb_base;
        Err("WoW64 FS setup unsupported on this target".to_string())
    }
}

pub fn current_teb32_base() -> u32 {
    CURRENT_TEB32.with(Cell::get)
}

pub fn create_teb32(image_base: u32) -> Teb32 {
    let mut teb = Teb32 { process_environment_block: image_base, ..Teb32::default() };
    teb.tib.self_ptr = (&teb.tib as *const NtTib32 as usize & 0xFFFF_FFFF) as u32;
    teb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_desc_points_to_teb_base() {
        let desc = build_user_desc(0x00AB_C000);
        assert_eq!(desc.base_addr, 0x00AB_C000);
        assert_eq!(desc.seg_32bit, 1);
    }

    #[test]
    fn create_teb32_sets_defaults() {
        let teb = create_teb32(0x0040_0000);
        assert_eq!(teb.process_environment_block, 0x0040_0000);
        assert_eq!(teb.tib.exception_list, 0xFFFF_FFFF);
    }
}
