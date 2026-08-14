# TuxExe-rs

TuxExe-rs is a Rust-based Windows PE compatibility layer for Linux. It allows execution of Windows `.exe` files natively on Linux systems without relying on full emulation, by mapping Windows APIs to Linux equivalents directly where possible, and employing WoW64-like translation for architectures.

## Architecture
See `docs/ARCHITECTURE.md` for a comprehensive overview of the design.

## DXVK runtime

The D3D11 path needs the TuxExe MS-ABI DXVK fork, not stock DXVK Native.
Release archives place its two shared libraries in `lib/tuxexe/dxvk/lib/`
(or `bin/dxvk/lib/` for a portable archive). The runtime discovers either
layout automatically. During development, the same layout is `runtime/dxvk/lib/`.

The bundled runtime is selected automatically. `TUXEXE_DXVK_DIR` is an
optional development override and must be paired with
`TUXEXE_DXVK_MSABI=1`; a stock SysV-ABI DXVK build must not be used because PE
x64 calls use the Windows ABI.

## Implementation Plan
See `docs/IMPLEMENTATION_PLAN.md` for the current progress and roadmaps.

## License
Provided under the MIT License. See `LICENSE` for the full text.
