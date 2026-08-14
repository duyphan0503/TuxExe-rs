#include <stdint.h>
#include <stdio.h>
#include <windows.h>

DWORD WINAPI thread_func(LPVOID arg) {
    printf("thread=%d\n", (int)(intptr_t)arg);
    return 0;
}

int main(void) {
    HANDLE threads[2];
    for (int i = 0; i < 2; ++i) {
        threads[i] = CreateThread(NULL, 0, thread_func, (LPVOID)(intptr_t)i, 0, NULL);
        if (!threads[i]) return 20 + i;
    }
    DWORD result = WaitForMultipleObjects(2, threads, TRUE, INFINITE);
    printf("wait=%lu\n", (unsigned long)result);
    return result == WAIT_OBJECT_0 ? 0 : 30;
}
