#![allow(
    non_snake_case,
    dead_code,
    unused_variables,
    unused_imports,
    unused_unsafe,
    function_casts_as_integer
)]

//! Win32 API subsystem — higher-level Windows APIs built on NT kernel emulation.

pub mod advapi32;
pub mod bcrypt;
pub mod crypt32;
pub mod dbghelp;
pub mod dinput8;
pub mod dsound;
pub mod dwmapi;
pub mod gdi32;
pub mod hid;
pub mod imm32;
pub mod kernel32;
pub mod msvcrt;
pub mod ole32;
pub mod oleaut32;
pub mod opengl32;
pub mod setupapi;
pub mod unityplayer;
pub mod shell32;
pub mod shlwapi;
pub mod user32;
pub mod version;
pub mod winhttp;
pub mod winmm;
pub mod ws2_32;
