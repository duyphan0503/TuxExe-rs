//! Thread Environment Block (TEB) — allocated per thread, set via arch_prctl(ARCH_SET_GS).

use std::alloc::{alloc, Layout};
use std::ptr;
use tracing::info;

#[repr(C, align(4096))]
struct NtTib {
    exception_list: *mut u8,      // 0x00
    stack_base: *mut u8,           // 0x08
    stack_limit: *mut u8,          // 0x10
    sub_system_tib: *mut u8,       // 0x18
    fiber_data: *mut u8,            // 0x20
    arbitrary_user_pointer: *mut u8, // 0x28
    self_ptr: *mut NtTib,          // 0x30
}

#[repr(C, align(4096))]
struct Peb {
    inherited_address_space: u8,
    read_image_file_exec_options: u8,
    being_debugged: u8,
    bit_field: u8,
    mutant: *mut u8,
    image_base_address: *mut u8,   // 0x10
    // ... more fields ...
}

/// A very minimal TEB for 64-bit Windows.
#[repr(C, align(4096))]
pub struct Teb {
    tib: NtTib,                    // 0x00
    environmental_pointer: *mut u8, // 0x38
    cid_unique_process: *mut u8,    // 0x40
    cid_unique_thread: *mut u8,     // 0x48
    active_rpc_handle: *mut u8,     // 0x50
    tls_pointer: *mut u8,           // 0x58
    peb: *mut Peb,                 // 0x60
    current_last_error: u32,       // 0x68
}

pub fn setup_teb(image_base: usize) -> Result<(), String> {
    unsafe {
        let teb_layout = Layout::new::<Teb>();
        let peb_layout = Layout::new::<Peb>();

        let teb_ptr = alloc(teb_layout) as *mut Teb;
        let peb_ptr = alloc(peb_layout) as *mut Peb;

        if teb_ptr.is_null() || peb_ptr.is_null() {
            return Err("Failed to allocate TEB/PEB".into());
        }

        ptr::write_bytes(teb_ptr, 0, 1);
        ptr::write_bytes(peb_ptr, 0, 1);

        // NT_TIB setup
        (*teb_ptr).tib.self_ptr = &mut (*teb_ptr).tib;
        
        // PEB setup
        (*teb_ptr).peb = peb_ptr;
        (*peb_ptr).image_base_address = image_base as *mut u8;

        info!(
            teb = format_args!("{:p}", teb_ptr),
            peb = format_args!("{:p}", peb_ptr),
            "Initialized dummy TEB/PEB"
        );

        #[cfg(target_os = "linux")]
        {
            const ARCH_SET_GS: libc::c_int = 0x1001;
            let ret = libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, teb_ptr as usize);
            if ret != 0 {
                return Err(format!(
                    "arch_prctl(ARCH_SET_GS) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            info!("Applied GS base via arch_prctl");
        }

        Ok(())
    }
}
