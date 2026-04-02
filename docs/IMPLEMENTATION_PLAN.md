# TuxExe-rs Implementation Plan

## Overview

This plan is designed for a **solo developer** with an **open-ended timeline**. Each phase produces a working, testable milestone. You can stop at any phase and have something useful.

---

## Phase 0: Foundation (Weeks 1-3)

**Goal**: Project skeleton, CI, and tooling.

### Tasks

- [x] 0.1 Set up project structure (all crate modules as empty `mod.rs` files)
- [x] 0.2 Configure `Cargo.toml` with initial dependencies (goblin, nix, libc, memmap2, tracing, thiserror, anyhow, clap)
- [x] 0.3 Create CLI entry point: `tuxexe <path-to-exe> [args...]`
- [x] 0.4 Set up tracing/logging infrastructure (structured logs with levels)
- [x] 0.5 Create `utils/wide_string.rs` — UTF-16LE ↔ UTF-8 conversion (needed everywhere)
- [x] 0.6 Create `utils/handle.rs` — HANDLE table (u32/u64 → trait object mapping)
- [x] 0.7 Set up GitHub Actions CI (cargo build, cargo test, cargo clippy, cargo fmt)
- [x] 0.8 Write a "hello world" Windows console .exe with MinGW for testing: `x86_64-w64-mingw32-gcc -o tests/test_binaries/hello.exe tests/test_binaries/hello.c`
- [x] 0.9 Add `docs/ARCHITECTURE.md` ✅ (done)

### Deliverable

Running `tuxexe hello.exe` prints a clear error: "PE loaded but no APIs implemented yet."

### Test

```bash
cargo build
cargo test
cargo clippy -- -D warnings
```

---

## Phase 1: PE Loader (Weeks 3-8)

**Goal**: Parse and memory-map a PE64 executable. No API execution yet.

### Tasks

- [x] 1.1 `pe_loader/parser.rs` — Parse PE headers using `goblin::pe::PE`
  - DOS header validation (MZ magic)
  - PE signature validation
  - COFF header (machine type, number of sections)
  - Optional header (PE32+ detection, entry point RVA, image base, section alignment)
  - Section headers (name, virtual address, virtual size, raw data pointer, characteristics)
- [x] 1.2 `pe_loader/mapper.rs` — Map PE sections into process memory
  - Calculate required address range from Optional Header's SizeOfImage
  - `mmap(MAP_ANONYMOUS | MAP_PRIVATE)` at preferred ImageBase (or any address if taken)
  - Copy each section's raw data into the mapped region at section's VirtualAddress offset
  - Set memory protection per section: `.text` → PROT_READ|PROT_EXEC, `.data` → PROT_READ|PROT_WRITE, `.rdata` → PROT_READ
  - Zero-fill BSS regions (virtual size > raw data size)
- [x] 1.3 `pe_loader/relocations.rs` — Process base relocations
  - Parse `.reloc` section (IMAGE_BASE_RELOCATION blocks)
  - Calculate delta = actual_base - preferred_base
  - Apply fixups: IMAGE_REL_BASED_DIR64 (add delta to u64), IMAGE_REL_BASED_HIGHLOW (add delta to u32)
- [x] 1.4 `pe_loader/imports.rs` — Parse Import Directory Table (skeleton)
  - Walk IMAGE_IMPORT_DESCRIPTOR array
  - For each DLL: read Import Name Table (INT) entries
  - Log all required DLLs and function names (don't resolve yet)
  - Detect import by name vs import by ordinal
- [x] 1.5 Unit tests with real PE binaries
  - Test with MinGW-compiled hello.exe
  - Test with a PE32 (32-bit) binary
  - Test section mapping correctness (read back mapped memory)
  - Test relocation application

### Deliverable

```
$ tuxexe hello.exe
[INFO] Loaded PE64: hello.exe
[INFO] ImageBase: 0x140000000, EntryPoint: 0x1400011a0
[INFO] Sections: .text (RX), .rdata (R), .data (RW), .bss (RW)
[INFO] Relocated: delta = 0x... (12 fixups applied)
[INFO] Imports required:
[INFO]   KERNEL32.dll: ExitProcess, GetStdHandle, WriteConsoleW, ...
[INFO]   msvcrt.dll: printf, exit, __argc, __argv, ...
[ERROR] Cannot execute: no API implementations available
```

---

## Phase 2: Minimal Execution — "Hello World" (Weeks 8-16)

**Goal**: Run a MinGW-compiled "Hello World" .exe that prints to stdout and exits.

### Required APIs (absolute minimum for hello.exe)

A MinGW hello world typically needs:

```
kernel32.dll: GetStdHandle, WriteFile/WriteConsoleA, ExitProcess,
              GetModuleHandleA, GetStartupInfoA, GetCommandLineA,
              SetUnhandledExceptionFilter, GetSystemTimeAsFileTime,
              GetCurrentThreadId, GetCurrentProcessId, QueryPerformanceCounter,
              IsProcessorFeaturePresent
msvcrt.dll:   __getmainargs, __set_app_type, _cexit, _amsg_exit,
              __p__fmode, __p__commode, _initterm, printf/puts, exit
```

### Tasks

- [x] 2.1 `utils/handle.rs` — Implement handle table
  - Thread-safe handle allocation (AtomicU32 counter)
  - Handle → Box<dyn HandleObject> lookup via DashMap or RwLock<HashMap>
  - Pre-allocate stdin/stdout/stderr handles
- [x] 2.2 `nt_kernel/file.rs` — Basic file operations
  - NtWriteFile → write() for console handles (stdout/stderr)
  - NtReadFile → read() for stdin
- [x] 2.3 `win32/kernel32/console.rs` — Console API
  - GetStdHandle → return pre-allocated handles (STD_INPUT=-10, STD_OUTPUT=-11, STD_ERROR=-12)
  - WriteConsoleA/W → write to stdout fd
  - WriteFile → write to file descriptor from handle table
- [x] 2.4 `win32/kernel32/process.rs` — Process basics
  - ExitProcess → std::process::exit()
  - GetModuleHandleA/W → return base address of loaded PE (NULL = main exe)
  - GetCommandLineA/W → construct from std::env::args()
  - GetStartupInfoA/W → return zeroed STARTUPINFO struct
  - GetCurrentProcessId → libc::getpid()
  - GetCurrentThreadId → libc::gettid()
  - IsProcessorFeaturePresent → hardcode common features
- [x] 2.5 `win32/kernel32/time.rs` — Time APIs
  - GetSystemTimeAsFileTime → clock_gettime → convert to FILETIME
  - QueryPerformanceCounter → clock_gettime(CLOCK_MONOTONIC)
  - QueryPerformanceFrequency → return 1_000_000_000 (ns)
  - GetTickCount → clock_gettime(CLOCK_MONOTONIC) in ms
- [x] 2.6 `win32/kernel32/error.rs` — Error handling
  - GetLastError / SetLastError → thread-local storage (std::cell::Cell<u32>)
  - SetUnhandledExceptionFilter → store callback, don't invoke yet
- [x] 2.7 `win32/msvcrt/mod.rs` — Minimal C runtime
  - \_\_getmainargs → parse argc/argv from command line
  - \_\_set_app_type → no-op (store value)
  - \_initterm → call function pointer array (C++ static initializers)
  - printf → delegate to Rust's libc::printf or implement with format parsing
  - puts → write string + newline to stdout
  - exit → ExitProcess
- [x] 2.8 `dll_manager/mod.rs` — DLL dispatch
  - When imports reference `kernel32.dll!GetStdHandle`, route to our Rust impl
  - Build a HashMap<(DllName, FuncName), fn pointer> dispatch table
  - Patch IAT entries to point to our Rust function implementations
- [x] 2.9 `pe_loader/imports.rs` — Complete IAT resolution
  - For each import: look up in dispatch table → get function pointer
  - Write function pointer into IAT slot in mapped memory
  - Handle thunking: Windows calling convention (x64: RCX,RDX,R8,R9) matches System V partially — may need shims
- [x] 2.10 Entry point execution
  - After IAT resolution, jump to AddressOfEntryPoint
  - Use `unsafe { std::mem::transmute }` to cast to `extern "C" fn()` and call
  - Set up minimal TEB before entry (at least FS/GS base with stack info)
- [x] 2.11 **CRITICAL**: Calling convention bridge
  - Windows x64: RCX, RDX, R8, R9, stack (callee cleans shadow space)
  - System V x64: RDI, RSI, RDX, RCX, R8, R9, stack
  - Write assembly thunks that convert between conventions
  - Each exported API function needs a thunk: recv Windows args → reorder → call Rust impl
  - Use `global_asm!` or `naked_fn` (nightly) or a code generator

### Deliverable

```
$ tuxexe hello.exe
Hello, World!
$ echo $?
0
```

### Critical Challenge: Calling Convention

This is the single hardest part of Phase 2. Windows x64 ABI differs from System V:

- Different register assignment (RCX vs RDI for first arg)
- Shadow space (32 bytes reserved on stack by caller in Windows)
- Different struct passing rules

**Solution**: Generate assembly trampolines for each API function. Example:

```asm
; Thunk for WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nBytes, LPDWORD written, LPOVERLAPPED ovlp)
; Windows: RCX=hFile, RDX=lpBuffer, R8=nBytes, R9=written, [RSP+40]=ovlp
; System V: RDI=hFile, RSI=lpBuffer, RDX=nBytes, RCX=written, R8=ovlp
thunk_WriteFile:
    mov rdi, rcx        ; hFile
    mov rsi, rdx        ; lpBuffer
    mov rdx, r8         ; nBytes
    mov rcx, r9         ; written
    mov r8, [rsp+40]    ; ovlp (from shadow space + stack)
    jmp rust_WriteFile   ; tail-call into Rust
```

---

## Phase 3: Memory & Threading (Weeks 16-24)

**Goal**: Support multi-threaded apps and dynamic memory allocation.

### Tasks

- [x] 3.1 `memory/virtual_alloc.rs` — VirtualAlloc/VirtualFree
  - MEM_RESERVE: mmap with PROT_NONE
  - MEM_COMMIT: mprotect to requested protection
  - MEM_RELEASE: munmap
  - Track allocations in a BTreeMap<usize, AllocationInfo>
- [x] 3.2 `memory/heap.rs` — HeapCreate/HeapAlloc/HeapFree
  - Default process heap → Rust global allocator
  - Custom heaps → tracked heap handles
  - HeapAlloc → malloc + track, HeapFree → free
- [x] 3.3 `threading/teb.rs` — Thread Environment Block
  - Allocate TEB struct (4KB) per thread
  - Set GS base via arch_prctl(ARCH_SET_GS) on x64
  - Fields: ExceptionList, StackBase, StackLimit, TlsSlots, LastError, PEB pointer
- [x] 3.4 `threading/tls.rs` — Thread Local Storage
  - TlsAlloc → allocate slot index (0-1087)
  - TlsSetValue/TlsGetValue → read/write TEB.TlsSlots[index]
  - PE TLS directory callbacks → call before process/thread entry
- [x] 3.5 `win32/kernel32/thread.rs` — Thread API
  - CreateThread → std::thread spawn with TEB setup wrapper
  - ExitThread → managed guest-thread exit path
  - GetCurrentThread → pseudo-handle (-2)
  - SuspendThread/ResumeThread → cooperative start gating (not full async suspension yet)
- [x] 3.6 `win32/kernel32/sync.rs` — Synchronization
  - Critical sections → recursive mutex-backed implementation
  - CreateMutex → waitable mutex handle
  - CreateEvent → condvar-backed event object
  - CreateSemaphore → condvar-backed semaphore object
  - WaitForSingleObject → object wait with timeout
  - WaitForMultipleObjects → handle-array wait support
- [x] 3.7 `exceptions/signals.rs` — Signal handler setup
  - [x] Register SIGSEGV, SIGFPE, SIGILL, SIGTRAP handlers via sigaction
  - [x] On signal: construct EXCEPTION_RECORD, walk SEH chain
  - [x] x64: parse .pdata for RUNTIME_FUNCTION unwind info
- [x] 3.8 Process Environment Block (PEB)
  - Allocate PEB with: ImageBaseAddress, ProcessHeap, ProcessParameters
  - ProcessParameters: CommandLine, CurrentDirectory, Environment

### Deliverable

A multi-threaded Windows console app works:

```c
// test_threads.c — compiled with MinGW
#include <windows.h>
#include <stdio.h>
DWORD WINAPI thread_func(LPVOID arg) {
    printf("Thread %d running\n", (int)(intptr_t)arg);
    return 0;
}
int main() {
    HANDLE threads[4];
    for (int i = 0; i < 4; i++)
        threads[i] = CreateThread(NULL, 0, thread_func, (LPVOID)(intptr_t)i, 0, NULL);
    WaitForMultipleObjects(4, threads, TRUE, INFINITE);
    printf("All threads done\n");
    return 0;
}
```

---

## Phase 4: File System & Registry (Weeks 24-32)

**Goal**: Apps can read/write files and access registry.

### Tasks

- [x] 4.1 `filesystem/path.rs` — Path translation
  - `C:\foo\bar` → `~/.tuxexe/drive_c/foo/bar`
  - Backslash → forward slash
  - Drive letter resolution from config
  - Special folders: %TEMP%, %USERPROFILE%, %APPDATA%
- [x] 4.2 `filesystem/case_fold.rs` — Case-insensitive filesystem
  - On file open: if exact path fails, scan directory for case-insensitive match
  - Cache results in LRU cache for performance
- [x] 4.3 `nt_kernel/file.rs` — Full file operations
  - NtCreateFile with full access mask, share mode, disposition handling
  - NtQueryInformationFile → fstat with struct conversion
  - NtSetInformationFile → ftruncate, rename, etc.
  - NtQueryDirectoryFile → getdents64 with FindFirstFile/FindNextFile semantics
  - File locking: NtLockFile → fcntl(F_SETLK)
- [x] 4.4 `win32/kernel32/file.rs` — Win32 file API
  - CreateFileA/W, ReadFile, WriteFile, CloseHandle
  - SetFilePointer/Ex → lseek
  - GetFileSize/Ex → fstat
  - FindFirstFileA/W, FindNextFileA/W → opendir/readdir
  - GetFileAttributesA/W → stat
  - CreateDirectoryA/W → mkdir
  - DeleteFileA/W → unlink
  - GetTempPathA/W → $TMPDIR or /tmp
- [x] 4.5 `registry/store.rs` — SQLite registry
  - Schema: `CREATE TABLE reg (path TEXT, name TEXT, type INT, data BLOB, PRIMARY KEY(path, name))`
  - RegOpenKeyExA/W → query existence
  - RegQueryValueExA/W → SELECT by path+name
  - RegSetValueExA/W → INSERT OR REPLACE
  - RegEnumKeyExA/W → SELECT DISTINCT child keys
  - RegDeleteKeyA/W → DELETE
- [x] 4.6 `registry/defaults.rs` — Minimal registry defaults
  - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion (SystemRoot, etc.)
  - HKCU\Environment
  - HKCR\.exe → exefile

### Deliverable

A Windows app can create, read, write files and query registry:

```c
// test_files.c
#include <windows.h>
#include <stdio.h>
int main() {
    HANDLE h = CreateFileA("test.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    WriteFile(h, "hello", 5, NULL, NULL);
    CloseHandle(h);
    // Read it back
    h = CreateFileA("test.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    char buf[256];
    DWORD read;
    ReadFile(h, buf, sizeof(buf), &read, NULL);
    CloseHandle(h);
    printf("Read: %.*s\n", read, buf);
    return 0;
}
```

---

## Phase 5: Dynamic DLL Loading (Weeks 32-38)

**Goal**: Support LoadLibrary, runtime DLL loading, and COM basics.

### Tasks

- [x] 5.1 LoadLibraryA/W — Search, load, and initialize DLLs at runtime
- [x] 5.2 GetProcAddress — Resolve exports from loaded DLLs
- [x] 5.3 FreeLibrary — Unload with reference counting
- [x] 5.4 DllMain entry point — Call with DLL_PROCESS_ATTACH/DETACH
- [x] 5.5 Delay-load imports — Handle delay-load directory
- [x] 5.6 Real Windows DLL loading — Load actual .dll binaries (hybrid approach)
  - Apply same PE loading pipeline as .exe
  - Resolve inter-DLL dependencies recursively
  - Handle DLL search paths and redirection

### Deliverable

Apps using LoadLibrary/GetProcAddress work. Plugin-based architectures supported.

---

## Phase 6: Networking (Weeks 38-44)

**Goal**: Winsock support for network-enabled applications.

### Tasks

- [x] 6.1 `win32/ws2_32/mod.rs` — Winsock API
  - WSAStartup/WSACleanup → no-op (Linux sockets always available)
  - socket → socket (nearly 1:1, translate AF_INET/SOCK_STREAM constants)
  - connect, bind, listen, accept → direct mapping
  - send/recv → send/recv (handle MSG\_\* flag differences)
  - select → select (translate fd_set format)
  - WSAGetLastError → errno mapping to WSA error codes
  - getaddrinfo/freeaddrinfo → direct mapping
- [x] 6.2 Async socket support
  - WSAAsyncSelect → epoll + callback
  - Overlapped I/O → io_uring or epoll wrapper

### Deliverable

A simple HTTP client or chat application works.

---

## Phase 7: GUI — X11/Wayland (Weeks 44-60+)

**Goal**: Basic windowed applications with GDI drawing.

### Tasks

- [x] 7.1 `win32/user32/window.rs` — Window management
  - RegisterClassA/W → internal class registry
  - CreateWindowExA/W → xcb_create_window / wayland surface
  - ShowWindow, MoveWindow, SetWindowPos → X11/Wayland equivalents
  - DestroyWindow → cleanup
- [x] 7.2 `win32/user32/message.rs` — Message loop
  - GetMessageA/W → blocking X11/Wayland event read
  - PeekMessageA/W → non-blocking poll
  - TranslateMessage → key translation
  - DispatchMessageA/W → call window procedure
  - PostQuitMessage → WM_QUIT
  - Map X11 events to Windows messages (KeyPress→WM_KEYDOWN, Expose→WM_PAINT, etc.)
- [x] 7.3 `win32/gdi32/mod.rs` — Basic drawing
  - BeginPaint/EndPaint → get drawing context
  - TextOutA/W → draw text (Xft or Pango)
  - Rectangle, Ellipse → X11 drawing primitives
  - BitBlt → image copy
  - CreateCompatibleDC, SelectObject → offscreen drawing
- [x] 7.4 Keyboard/Mouse input mapping
  - X11 keysym → Windows virtual key codes
  - Mouse events → WM_MOUSEMOVE, WM_LBUTTONDOWN, etc.

### Deliverable

A basic Win32 GUI app with a window, message loop, and text drawing works.

---

## Phase 8: DXVK Integration (Weeks 60-80+)

**Goal**: DirectX 9/10/11 games render via Vulkan.

### Tasks

- [x] 8.1 Build DXVK as standalone .so libraries
- [x] 8.2 Create Wine API shim layer for DXVK's dependencies
- [x] 8.3 HWND → X11 Window / Vulkan surface bridging
- [x] 8.4 DirectInput → evdev/libinput mapping
- [x] 8.5 DirectSound → PipeWire/PulseAudio mapping
- [x] 8.6 Test with simple DirectX demo apps

### Deliverable

A DirectX 11 demo app renders correctly via Vulkan.

---

## Phase 9: WoW64 — 32-bit Support (Weeks 80-100+)

**Goal**: Run 32-bit PE32 executables on 64-bit Linux.

### Tasks

- [x] 9.1 Reserve low 4GB address space on startup
- [x] 9.2 PE32 loader variant (32-bit headers, 32-bit relocations)
- [x] 9.3 FS segment register setup for 32-bit TEB (modify_ldt)
- [x] 9.4 32→64 thunking layer for API calls
- [x] 9.5 Separate 32-bit DLL set (SysWOW64 equivalent)
- [x] 9.6 x86 SEH (frame-based, FS:[0] chain)

### Deliverable

A 32-bit Windows console app runs on 64-bit Linux.

Current runtime behavior: `tuxexe run` delegates x86 execution to an external backend by default (`TUXEXE_X86_BACKEND=wine`). Set `TUXEXE_X86_BACKEND=native` to force in-process experimental path.

---

## Phase 10+: Advanced Features (Ongoing)

- [ ] COM/OLE/ActiveX basics (CoCreateInstance, IUnknown)
- [ ] Windows Services emulation
- [ ] Named pipes (CreateNamedPipe)
- [x] Memory-mapped files (CreateFileMapping/MapViewOfFile)
- [ ] I/O Completion Ports → io_uring
- [ ] Windows Installer (MSI) basics
- [ ] .NET CLR hosting (via Mono/CoreCLR)
- [ ] Audio: DirectSound/WASAPI → PipeWire
- [ ] Printing: GDI printing → CUPS
- [ ] Clipboard: Windows clipboard → X11 selection

---

## Milestone Tracker

| Phase | Milestone                          | Status | Validates             |
| ----- | ---------------------------------- | ------ | --------------------- |
| 0     | Project skeleton builds & tests    | ✅     | Tooling               |
| 1     | PE headers parsed, sections mapped | ✅     | PE loader correctness |
| 2     | **hello.exe prints "Hello World"** | ✅     | End-to-end execution  |
| 3     | Multi-threaded app works           | 🟨     | Threading + sync      |
| 4     | File I/O + registry queries work   | ✅     | OS services           |
| 5     | LoadLibrary + DLL plugins work     | ✅     | Dynamic loading       |
| 6     | HTTP client app works              | ✅     | Networking            |
| 7     | Win32 GUI window appears           | 🟨     | Graphics pipeline     |
| 8     | DirectX demo renders               | ✅     | DXVK integration      |
| 9     | 32-bit exe runs on 64-bit          | ✅     | WoW64                 |

**The critical milestone is Phase 2**: once "Hello World" runs, everything else is incremental API coverage.

---

## References

- [Wine Developer's Guide](https://wiki.winehq.org/Developer_Hints)
- [ReactOS Source](https://github.com/nicedoc/reactos) — Clean-room Windows reimplementation
- [PE Format Specification (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Windows Internals, 7th Edition](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals) — Bible for NT kernel internals
- [DXVK Source](https://github.com/doitsujin/dxvk)
- [goblin crate docs](https://docs.rs/goblin)
- [nix crate docs](https://docs.rs/nix)
