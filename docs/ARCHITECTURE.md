# TuxExe-rs Architecture Document

## Vision
A Rust-based Windows application compatibility layer for Linux that can run PE (.exe/.dll) executables natively, replacing Wine with a focus on **performance** and **memory safety**.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Target PE format | PE32 + PE32+ (both) | Full 32-bit and 64-bit compatibility |
| Syscall strategy | User-space NT→Linux translation | No kernel module needed initially; kernel module as future optimization |
| Graphics | Reuse DXVK/vkd3d-proton | Proven DirectX→Vulkan translation; focus Rust effort on core runtime |
| DLL strategy | Hybrid (Rust reimpl + real DLL loading) | Reimplement critical DLLs, load real Windows DLLs as fallback |
| Language | Rust | Memory safety, performance, modern tooling |
| Primary motivation | Performance improvement over Wine | Rust's zero-cost abstractions + modern design |

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows Application (.exe)                │
├─────────────────────────────────────────────────────────────┤
│                     TuxExe-rs Runtime                        │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  PE Loader   │  │ DLL Manager  │  │  Memory Manager    │  │
│  │  (parse/map) │  │ (IAT/hybrid) │  │  (virtual alloc)   │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬───────────┘  │
│         │                 │                    │              │
│  ┌──────┴─────────────────┴────────────────────┴───────────┐ │
│  │              Win32 API Subsystem                         │ │
│  │  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌─────────────┐  │ │
│  │  │kernel32  │ │ user32   │ │ gdi32  │ │  advapi32   │  │ │
│  │  │(files,   │ │(windows, │ │(draw,  │ │(registry,   │  │ │
│  │  │ process, │ │ msg loop,│ │ fonts, │ │ crypto,     │  │ │
│  │  │ thread,  │ │ input)   │ │ bitmap)│ │ services)   │  │ │
│  │  │ sync)    │ │          │ │        │ │             │  │ │
│  │  └──────────┘ └──────────┘ └────────┘ └─────────────┘  │ │
│  │  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌─────────────┐  │ │
│  │  │ ntdll    │ │ msvcrt   │ │ws2_32  │ │  ole32      │  │ │
│  │  │(NT API,  │ │(C runtime│ │(socket)│ │(COM/OLE)    │  │ │
│  │  │ syscalls)│ │          │ │        │ │             │  │ │
│  │  └──────────┘ └──────────┘ └────────┘ └─────────────┘  │ │
│  └──────────────────────┬──────────────────────────────────┘ │
│                         │                                    │
│  ┌──────────────────────┴──────────────────────────────────┐ │
│  │           NT Kernel Emulation Layer (ntoskrnl)           │ │
│  │  ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │ │
│  │  │ Object    │ │ I/O      │ │ Process  │ │ Registry │  │ │
│  │  │ Manager   │ │ Manager  │ │ Manager  │ │ Manager  │  │ │
│  │  └───────────┘ └──────────┘ └──────────┘ └──────────┘  │ │
│  └──────────────────────┬──────────────────────────────────┘ │
│                         │                                    │
│  ┌──────────────────────┴──────────────────────────────────┐ │
│  │            Linux Syscall Translation Layer               │ │
│  │  NT syscall → POSIX/Linux syscall mapping                │ │
│  │  Signal handlers ↔ SEH (Structured Exception Handling)   │ │
│  │  Windows threads → pthreads                              │ │
│  │  NTFS semantics → ext4/btrfs                             │ │
│  └──────────────────────┬──────────────────────────────────┘ │
├──────────────────────────┼──────────────────────────────────┤
│  ┌──────────────────────┴──────────────────────────────────┐ │
│  │              WoW64 Subsystem (32-on-64)                  │ │
│  │  Thunking layer for 32-bit PE32 on 64-bit Linux          │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐ │
│  │         External Integrations (FFI boundaries)           │ │
│  │  DXVK (DirectX 9/10/11→Vulkan)                          │ │
│  │  vkd3d-proton (DirectX 12→Vulkan)                        │ │
│  │  X11/Wayland (window management)                         │ │
│  │  PulseAudio/PipeWire (audio)                             │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. PE Loader (`crate::pe_loader`)

Responsible for parsing and loading PE32/PE32+ executables into process memory.

**Key responsibilities:**
- Parse DOS header, PE signature, COFF header, Optional header
- Map sections (.text, .data, .rdata, .bss, .rsrc) into memory with correct permissions (RX, RW, R)
- Handle ASLR / preferred base address relocation
- Process base relocations (.reloc section) when image can't load at preferred address
- Resolve imports via Import Address Table (IAT)
- Execute TLS callbacks before entry point
- Support both PE32 (32-bit, `IMAGE_OPTIONAL_HEADER32`) and PE32+ (64-bit, `IMAGE_OPTIONAL_HEADER64`)

**Rust crates:**
- `goblin` — PE/ELF/Mach-O parser (primary choice, well-maintained)
- `memmap2` — memory-mapped file I/O
- `region` — cross-platform memory protection (mprotect wrapper)

**PE32 vs PE32+ differences:**
| Field | PE32 | PE32+ |
|-------|------|-------|
| Magic | 0x10B | 0x20B |
| ImageBase | u32 | u64 |
| SizeOfStackReserve | u32 | u64 |
| SizeOfHeapReserve | u32 | u64 |
| BaseOfData | Present | Absent |
| AddressOfEntryPoint | RVA (u32) | RVA (u32) |

### 2. DLL Manager (`crate::dll_manager`)

Hybrid DLL loading system that can:
1. **Rust-native DLLs**: Built-in reimplementations of critical Windows DLLs
2. **Real DLL loading**: Load actual Windows DLL binaries (from a Windows installation or redistributables)
3. **Fallback chain**: Try Rust-native first → real DLL → error

**Module search order (matching Windows):**
1. Application directory
2. System directory (emulated `C:\Windows\System32\`)
3. Windows directory (emulated `C:\Windows\`)
4. Current directory
5. PATH directories

**Export resolution:**
- Parse Export Directory Table from DLL
- Resolve by name (most common) or by ordinal
- Handle forwarded exports (e.g., kernel32!HeapAlloc → ntdll!RtlAllocateHeap)

### 3. NT Kernel Emulation (`crate::nt_kernel`)

The core translation layer. Windows applications ultimately call NT kernel functions (via ntdll.dll). This component translates those to Linux equivalents.

**Critical NT APIs to implement first:**

| NT API | Linux Equivalent | Priority |
|--------|-----------------|----------|
| NtCreateFile | open/openat | P0 |
| NtReadFile | read/pread64 | P0 |
| NtWriteFile | write/pwrite64 | P0 |
| NtClose | close | P0 |
| NtCreateProcess/Ex | fork+exec / clone | P0 |
| NtCreateThread/Ex | clone / pthread_create | P0 |
| NtAllocateVirtualMemory | mmap | P0 |
| NtFreeVirtualMemory | munmap | P0 |
| NtProtectVirtualMemory | mprotect | P0 |
| NtQueryInformationFile | fstat/statx | P0 |
| NtWaitForSingleObject | futex / pthread_mutex | P1 |
| NtCreateEvent | eventfd | P1 |
| NtCreateMutant | futex / pthread_mutex | P1 |
| NtCreateSemaphore | sem_init | P1 |
| NtQuerySystemInformation | /proc/*, sysinfo | P1 |
| NtCreateKey (Registry) | Custom registry store | P2 |
| NtQueryValueKey | Custom registry store | P2 |
| NtDeviceIoControlFile | ioctl | P2 |

### 4. Win32 API Subsystem (`crate::win32`)

Higher-level Windows APIs built on top of NT kernel emulation.

**Module priority:**

**Phase 1 — kernel32.dll (Critical)**
- File I/O: CreateFileA/W, ReadFile, WriteFile, CloseHandle
- Process: CreateProcessA/W, ExitProcess, GetExitCodeProcess
- Thread: CreateThread, ExitThread, WaitForSingleObject
- Memory: VirtualAlloc, VirtualFree, VirtualProtect, HeapCreate/Alloc/Free
- Sync: CreateMutexA/W, CreateEventA/W, CreateSemaphoreA/W, EnterCriticalSection
- String: lstrlenA/W, lstrcpyA/W, MultiByteToWideChar, WideCharToMultiByte
- Console: GetStdHandle, WriteConsoleA/W, ReadConsoleA/W, SetConsoleMode
- Module: GetModuleHandleA/W, GetProcAddress, LoadLibraryA/W
- Error: GetLastError, SetLastError
- Environment: GetEnvironmentVariableA/W, GetCommandLineA/W
- Time: GetTickCount, QueryPerformanceCounter, GetSystemTimeAsFileTime

**Phase 2 — msvcrt.dll (C Runtime)**
- Standard C library functions (printf, malloc, fopen, etc.)
- Can delegate most to libc via FFI
- Must handle Windows-specific extensions (_beginthread, _aligned_malloc, etc.)

**Phase 3 — user32.dll + gdi32.dll (GUI)**
- Window management: CreateWindowExA/W, ShowWindow, UpdateWindow
- Message loop: GetMessageA/W, TranslateMessage, DispatchMessageA/W
- Drawing: BeginPaint, EndPaint, TextOutA/W
- Map to X11/Wayland via xcb/wayland-client crates

**Phase 4 — advapi32.dll (System Services)**
- Registry: RegOpenKeyExA/W, RegQueryValueExA/W, RegSetValueExA/W
- Security: OpenProcessToken, LookupPrivilegeValue

**Phase 5 — ws2_32.dll (Networking)**
- Winsock: WSAStartup, socket, connect, send, recv
- Map to Linux socket API (nearly 1:1)

**Phase 6+ — COM, OLE, Shell, etc.**

### 5. Memory Manager (`crate::memory`)

Windows has a different memory model than Linux. Key differences to handle:

- **VirtualAlloc/VirtualFree**: Map to mmap/munmap with matching semantics
  - MEM_COMMIT, MEM_RESERVE, MEM_RELEASE states
  - Page-level protection (PAGE_EXECUTE_READ, PAGE_READWRITE, etc.)
- **Heap API**: HeapCreate creates private heaps; map to custom allocator or jemalloc
- **Section objects**: NtCreateSection / MapViewOfSection for shared memory and file mapping
- **Address space layout**: Reserve low 2GB for 32-bit compatibility (WoW64)

### 6. Exception Handling (`crate::exceptions`)

Windows Structured Exception Handling (SEH) must be emulated via Linux signals:

| Windows Exception | Linux Signal |
|-------------------|-------------|
| ACCESS_VIOLATION | SIGSEGV |
| ILLEGAL_INSTRUCTION | SIGILL |
| INT_DIVIDE_BY_ZERO | SIGFPE |
| BREAKPOINT | SIGTRAP |
| STACK_OVERFLOW | SIGSEGV (alt stack) |

**Implementation approach:**
1. Register signal handlers for SIGSEGV, SIGILL, SIGFPE, SIGTRAP
2. In the handler, construct a Windows `EXCEPTION_RECORD` and `CONTEXT`
3. Walk the exception handler chain registered via `__try`/`__except` (stored in TEB/TIB)
4. For x64: Parse `.pdata` section (RUNTIME_FUNCTION entries) for table-based unwinding
5. For x86: Walk the FS:[0] exception handler chain (frame-based)

### 7. Threading & TLS (`crate::threading`)

**Thread Environment Block (TEB):**
Every Windows thread has a TEB accessible via FS (x86) or GS (x64) segment register.

- Use `arch_prctl(ARCH_SET_GS)` on x64 Linux to set GS base
- Use `set_thread_area()` or `modify_ldt()` on x86 for FS base
- Allocate TEB struct per thread with:
  - Exception handler list (FS:[0] on x86)
  - Stack base/limit
  - TLS slots (64 static + dynamic)
  - Last error value
  - PEB pointer

**Thread creation:**
- `CreateThread` → `pthread_create` with a wrapper that sets up TEB
- Windows thread priority → Linux nice values / `sched_setscheduler`

### 8. Filesystem Virtualization (`crate::filesystem`)

Map Windows filesystem semantics to Linux:

| Windows | Linux Mapping |
|---------|--------------|
| `C:\Windows\System32\` | `~/.tuxexe/drive_c/windows/system32/` |
| `C:\Users\<user>\` | `~/.tuxexe/drive_c/users/<user>/` → symlink to `$HOME` |
| `\\` path separator | `/` |
| Case-insensitive | Case-folding lookup layer |
| Drive letters (C:, D:) | Configurable mount points |
| `\\.\` device paths | `/dev/*` mapping |
| NTFS streams | xattr or separate files |

**Case insensitivity:** Implement a lookup cache that does case-folding on first access, then caches the real filesystem path.

### 9. Registry Emulation (`crate::registry`)

Implement Windows registry as a persistent key-value store:

- **Storage**: SQLite database or custom binary format at `~/.tuxexe/registry/`
- **Hives**: HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, etc.
- **Types**: REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ, REG_EXPAND_SZ
- **Predefined keys**: Populate with minimal defaults (SystemRoot, ComSpec, etc.)
- **Performance**: In-memory cache with write-back to disk

### 10. WoW64 Subsystem (`crate::wow64`)

Running 32-bit PE32 on a 64-bit Linux host:

- **Address space**: Reserve low 4GB of address space for 32-bit code
- **Thunking**: Convert 32-bit API calls to 64-bit internal calls
- **Segment registers**: Set up FS for 32-bit TEB via `modify_ldt`
- **Parameter marshaling**: Extend 32-bit pointers to 64-bit for internal APIs
- **Separate DLL sets**: Maintain both `system32/` (64-bit) and `syswow64/` (32-bit) DLLs

---

## External Integrations

### DXVK / vkd3d-proton Integration

DXVK provides DirectX 9/10/11 → Vulkan translation as `.so` libraries.

**Integration approach:**
1. Build DXVK as shared libraries (`.so`) — they expose DirectX COM interfaces
2. When the PE app loads `d3d11.dll` or `d3d9.dll`, redirect to DXVK's `.so`
3. DXVK needs a Vulkan instance → use `ash` or `vulkano` crate for Vulkan loader
4. Window handle translation: DXVK expects HWND → map to X11 Window / Wayland surface

**Note:** DXVK currently depends on Wine headers/APIs for some functionality. We may need to provide compatibility shims.

### X11 / Wayland Integration

For GUI apps, map Windows window management to X11/Wayland:

- `CreateWindow` → `xcb_create_window` or `wl_compositor.create_surface`
- Message pump → X11 event loop / Wayland event dispatch
- Prefer Wayland for modern systems, X11 as fallback
- Crates: `x11rb` (X11), `wayland-client` (Wayland), `winit` (abstraction)

### Audio (PulseAudio / PipeWire)

- Map Windows audio APIs (DirectSound, WASAPI, WinMM) to PipeWire/PulseAudio
- Crates: `libpulse-binding`, `pipewire` crate

---

## Crate Dependencies (Initial)

```toml
[dependencies]
# PE parsing
goblin = "0.9"

# Memory management
memmap2 = "0.9"
region = "3"

# Linux syscalls
nix = { version = "0.29", features = ["mman", "signal", "pthread", "fs"] }
libc = "0.2"

# Filesystem
walkdir = "2"

# Registry storage
rusqlite = { version = "0.32", features = ["bundled"] }

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

# Error handling
thiserror = "2"
anyhow = "1"

# CLI
clap = { version = "4", features = ["derive"] }

# Async (for I/O completion ports emulation, later)
tokio = { version = "1", features = ["full"], optional = true }
```

---

## Project Structure

```
tuxexe-rs/
├── Cargo.toml
├── docs/
│   ├── ARCHITECTURE.md          # This file
│   └── IMPLEMENTATION_PLAN.md   # Phase-by-phase plan
├── src/
│   ├── main.rs                  # CLI entry point
│   ├── lib.rs                   # Library root
│   ├── pe_loader/
│   │   ├── mod.rs
│   │   ├── parser.rs            # PE header parsing
│   │   ├── mapper.rs            # Section mapping into memory
│   │   ├── relocations.rs       # Base relocation processing
│   │   └── imports.rs           # IAT resolution
│   ├── dll_manager/
│   │   ├── mod.rs
│   │   ├── search.rs            # DLL search order
│   │   ├── native_dlls/         # Rust-reimplemented DLLs
│   │   │   ├── kernel32.rs
│   │   │   ├── ntdll.rs
│   │   │   ├── msvcrt.rs
│   │   │   └── ...
│   │   └── loader.rs            # Real DLL binary loading
│   ├── nt_kernel/
│   │   ├── mod.rs
│   │   ├── file.rs              # NtCreateFile, NtReadFile, etc.
│   │   ├── process.rs           # NtCreateProcess, etc.
│   │   ├── thread.rs            # NtCreateThread, etc.
│   │   ├── memory.rs            # NtAllocateVirtualMemory, etc.
│   │   ├── sync.rs              # NtWaitForSingleObject, events, mutexes
│   │   ├── registry.rs          # NtCreateKey, NtQueryValueKey
│   │   └── objects.rs           # Object manager (handles)
│   ├── win32/
│   │   ├── mod.rs
│   │   ├── kernel32/
│   │   │   ├── mod.rs
│   │   │   ├── file.rs
│   │   │   ├── process.rs
│   │   │   ├── thread.rs
│   │   │   ├── memory.rs
│   │   │   ├── sync.rs
│   │   │   ├── console.rs
│   │   │   └── string.rs
│   │   ├── user32/
│   │   ├── gdi32/
│   │   ├── advapi32/
│   │   ├── ws2_32/
│   │   └── msvcrt/
│   ├── memory/
│   │   ├── mod.rs
│   │   ├── virtual_alloc.rs     # VirtualAlloc/Free emulation
│   │   ├── heap.rs              # HeapCreate/Alloc/Free
│   │   └── section.rs           # Section objects (file mapping)
│   ├── exceptions/
│   │   ├── mod.rs
│   │   ├── seh.rs               # SEH chain walking
│   │   ├── signals.rs           # Linux signal → Windows exception
│   │   └── unwind.rs            # x64 table-based unwinding
│   ├── threading/
│   │   ├── mod.rs
│   │   ├── teb.rs               # Thread Environment Block
│   │   ├── tls.rs               # Thread Local Storage
│   │   └── scheduler.rs         # Thread priority mapping
│   ├── filesystem/
│   │   ├── mod.rs
│   │   ├── path.rs              # Windows↔Linux path conversion
│   │   ├── drives.rs            # Drive letter mapping
│   │   └── case_fold.rs         # Case-insensitive lookup
│   ├── registry/
│   │   ├── mod.rs
│   │   ├── store.rs             # SQLite-backed registry
│   │   ├── hive.rs              # Registry hive management
│   │   └── defaults.rs          # Default registry values
│   ├── wow64/
│   │   ├── mod.rs
│   │   ├── thunk.rs             # 32→64 bit thunking
│   │   └── address_space.rs     # Low 4GB reservation
│   └── utils/
│       ├── mod.rs
│       ├── wide_string.rs       # UTF-16 ↔ UTF-8 conversion
│       └── handle.rs            # Windows HANDLE management
├── tests/
│   ├── pe_loading_tests.rs
│   ├── win32_api_tests.rs
│   └── test_binaries/           # Small .exe files for testing
└── tools/
    └── api_coverage.rs          # Track which APIs are implemented
```

---

## Performance Strategy (vs Wine)

1. **Zero-copy PE loading**: `mmap` PE directly, avoid copying sections
2. **Lock-free handle table**: Use atomic operations for HANDLE→object lookup
3. **Inline fast paths**: Common APIs (GetLastError, SetLastError) as direct TEB field access
4. **Batch syscall translation**: Group related NT calls where possible
5. **Custom allocator**: Pool allocator for HeapAlloc (avoid malloc overhead)
6. **Profile-guided**: Instrument hot API calls, optimize the top 20%
7. **Future kernel module**: Bypass user-space translation for hot syscalls

---

## Testing Strategy

1. **Unit tests**: Each NT API translation tested in isolation
2. **API conformance tests**: Port Wine's conformance test suite concepts
3. **Binary test suite**: Compile small C programs with MSVC/MinGW, verify they run
4. **Regression tests**: Known Windows apps that should work at each phase
5. **Benchmarks**: Compare API call latency vs Wine vs native Windows (in VM)

---

## Risk Analysis

| Risk | Severity | Mitigation |
|------|----------|------------|
| API surface is enormous (~20,000+ Win32 functions) | Critical | Implement incrementally; track coverage; focus on most-used APIs |
| Some apps depend on undocumented Windows behavior | High | Use Wine source + ReactOS as reference for edge cases |
| DXVK may have hard Wine dependencies | High | Audit DXVK's Wine API usage; create compatibility shims |
| SEH emulation is notoriously difficult | High | Start with x64 table-based (simpler); add x86 frame-based later |
| 32-bit support requires careful address space management | Medium | Defer WoW64 until 64-bit support is solid |
| Solo developer burnout on massive project | High | Incremental milestones; celebrate each working app |
