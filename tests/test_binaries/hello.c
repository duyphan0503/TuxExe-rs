/*
 * hello.c — minimal Windows console "Hello World" for TuxExe-rs testing.
 *
 * Compile with MinGW-w64 (produces a PE64 / PE32+ EXE):
 *
 *   x86_64-w64-mingw32-gcc -o hello.exe hello.c -static
 *
 * The -static flag links the C runtime statically so the binary has
 * no DLL dependencies — useful for Phase 0/1 testing before we implement
 * DLL loading.
 *
 * What this binary does:
 *   1. Prints "Hello, TuxExe-rs!\n" via printf (msvcrt.dll or statically linked).
 *   2. Returns exit code 0.
 *
 * Win32 API calls made internally by the C runtime startup:
 *   kernel32.dll:
 *     GetStartupInfoA, GetCommandLineA, ExitProcess,
 *     SetUnhandledExceptionFilter, IsProcessorFeaturePresent,
 *     QueryPerformanceCounter, GetCurrentProcessId, GetCurrentThreadId,
 *     GetSystemTimeAsFileTime
 */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    printf("Hello, TuxExe-rs!\n");
    fflush(stdout);
    return 0;
}
