# TuxExe-rs

TuxExe-rs is a Rust-based Windows PE compatibility layer for Linux. It allows execution of Windows `.exe` files natively on Linux systems without relying on full emulation, by mapping Windows APIs to Linux equivalents directly where possible, and employing WoW64-like translation for architectures.

## Architecture
See `docs/ARCHITECTURE.md` for a comprehensive overview of the design.

## Implementation Plan
See `docs/IMPLEMENTATION_PLAN.md` for the current progress and roadmaps.

## License
Provided under the MIT License. See `LICENSE` for the full text.
