//! Dialog APIs - MessageBox, etc.

use std::ffi::CStr;
use std::process::Command;

// MessageBox constants
pub const MB_OK: u32 = 0x00000000;
pub const MB_OKCANCEL: u32 = 0x00000001;
pub const MB_ABORTRETRYIGNORE: u32 = 0x00000002;
pub const MB_YESNOCANCEL: u32 = 0x00000003;
pub const MB_YESNO: u32 = 0x00000004;
pub const MB_RETRYCANCEL: u32 = 0x00000005;

pub const MB_ICONERROR: u32 = 0x00000010;
pub const MB_ICONQUESTION: u32 = 0x00000020;
pub const MB_ICONWARNING: u32 = 0x00000030;
pub const MB_ICONINFORMATION: u32 = 0x00000040;

// Return values
pub const IDOK: i32 = 1;
pub const IDCANCEL: i32 = 2;
pub const IDABORT: i32 = 3;
pub const IDRETRY: i32 = 4;
pub const IDIGNORE: i32 = 5;
pub const IDYES: i32 = 6;
pub const IDNO: i32 = 7;

/// MessageBoxA - Display message box (ANSI)
#[no_mangle]
pub extern "win64" fn MessageBoxA(
    _hWnd: usize,
    lpText: *const u8,
    lpCaption: *const u8,
    uType: u32,
) -> i32 {
    tracing::debug!("MessageBoxA called");

    if lpText.is_null() {
        return IDOK;
    }

    unsafe {
        let text = CStr::from_ptr(lpText as *const i8)
            .to_string_lossy()
            .to_string();

        let caption = if lpCaption.is_null() {
            "TuxExe Application".to_string()
        } else {
            CStr::from_ptr(lpCaption as *const i8)
                .to_string_lossy()
                .to_string()
        };

        show_message_box(&text, &caption, uType)
    }
}

/// MessageBoxW - Display message box (Unicode)
#[no_mangle]
pub extern "win64" fn MessageBoxW(
    _hWnd: usize,
    lpText: *const u16,
    lpCaption: *const u16,
    uType: u32,
) -> i32 {
    tracing::debug!("MessageBoxW called");

    if lpText.is_null() {
        return IDOK;
    }

    let text = crate::utils::wide_string::wide_to_string(lpText);

    let caption = if lpCaption.is_null() {
        "TuxExe Application".to_string()
    } else {
        crate::utils::wide_string::wide_to_string(lpCaption)
    };

    show_message_box(&text, &caption, uType)
}

fn show_message_box(text: &str, caption: &str, uType: u32) -> i32 {
    tracing::info!("MessageBox: {} - {}", caption, text);

    // Extract button type and icon type
    let button_type = uType & 0x0F;
    let icon_type = uType & 0xF0;

    // Try to use zenity if available (GNOME)
    if let Ok(result) = show_zenity_dialog(text, caption, button_type, icon_type) {
        return result;
    }

    // Try kdialog (KDE)
    if let Ok(result) = show_kdialog_dialog(text, caption, button_type, icon_type) {
        return result;
    }

    // Fallback: Print to stderr and return default
    eprintln!("╔═══════════════════════════════════════╗");
    eprintln!("║ {:<38}║", caption);
    eprintln!("╠═══════════════════════════════════════╣");
    for line in text.lines() {
        eprintln!("║ {:<38}║", line);
    }
    eprintln!("╚═══════════════════════════════════════╝");

    // Return default button
    match button_type {
        MB_OK => IDOK,
        MB_OKCANCEL => IDOK,
        MB_YESNO | MB_YESNOCANCEL => IDYES,
        MB_RETRYCANCEL => IDRETRY,
        MB_ABORTRETRYIGNORE => IDABORT,
        _ => IDOK,
    }
}

fn show_zenity_dialog(text: &str, caption: &str, button_type: u32, icon_type: u32) -> Result<i32, ()> {
    // Check if zenity is available
    if Command::new("which").arg("zenity").output().is_err() {
        return Err(());
    }

    let mut cmd = Command::new("zenity");

    // Set icon type
    match icon_type {
        MB_ICONERROR => { cmd.arg("--error"); }
        MB_ICONWARNING => { cmd.arg("--warning"); }
        MB_ICONINFORMATION => { cmd.arg("--info"); }
        MB_ICONQUESTION => { cmd.arg("--question"); }
        _ => { cmd.arg("--info"); }
    }

    cmd.arg("--title").arg(caption);
    cmd.arg("--text").arg(text);
    cmd.arg("--no-markup");

    // Set button type
    match button_type {
        MB_OK => {
            cmd.arg("--ok-label=OK");
        }
        MB_OKCANCEL => {
            cmd.arg("--ok-label=OK");
            cmd.arg("--cancel-label=Cancel");
        }
        MB_YESNO => {
            cmd.arg("--ok-label=Yes");
            cmd.arg("--cancel-label=No");
        }
        MB_YESNOCANCEL => {
            cmd.arg("--ok-label=Yes");
            cmd.arg("--cancel-label=No");
            cmd.arg("--extra-button=Cancel");
        }
        _ => {}
    }

    let output = cmd.output().map_err(|_| ())?;

    // Check exit status
    if output.status.success() {
        Ok(match button_type {
            MB_YESNO | MB_YESNOCANCEL => IDYES,
            MB_RETRYCANCEL => IDRETRY,
            _ => IDOK,
        })
    } else {
        Ok(match button_type {
            MB_OKCANCEL | MB_YESNOCANCEL | MB_RETRYCANCEL => IDCANCEL,
            MB_YESNO => IDNO,
            _ => IDOK,
        })
    }
}

fn show_kdialog_dialog(text: &str, caption: &str, button_type: u32, icon_type: u32) -> Result<i32, ()> {
    // Check if kdialog is available
    if Command::new("which").arg("kdialog").output().is_err() {
        return Err(());
    }

    let mut cmd = Command::new("kdialog");

    cmd.arg("--title").arg(caption);

    // Set message type
    match icon_type {
        MB_ICONERROR => { cmd.arg("--error"); }
        MB_ICONWARNING => { cmd.arg("--sorry"); }
        MB_ICONINFORMATION => { cmd.arg("--msgbox"); }
        MB_ICONQUESTION => {
            match button_type {
                MB_YESNO | MB_YESNOCANCEL => { cmd.arg("--yesno"); }
                MB_OKCANCEL => { cmd.arg("--yesno"); }
                _ => { cmd.arg("--msgbox"); }
            }
        }
        _ => { cmd.arg("--msgbox"); }
    }

    cmd.arg(text);

    let output = cmd.output().map_err(|_| ())?;

    if output.status.success() {
        Ok(match button_type {
            MB_YESNO | MB_YESNOCANCEL => IDYES,
            _ => IDOK,
        })
    } else {
        Ok(match button_type {
            MB_OKCANCEL | MB_YESNOCANCEL => IDCANCEL,
            MB_YESNO => IDNO,
            _ => IDOK,
        })
    }
}
