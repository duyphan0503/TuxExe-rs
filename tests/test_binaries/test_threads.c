#include <stdint.h>
#include <stdio.h>
#include <windows.h>

DWORD WINAPI thread_func(LPVOID arg) {
    printf("Thread %d running\n", (int)(intptr_t)arg);
    return 0;
}

int main(void) {
    HANDLE threads[4];

    for (int i = 0; i < 4; i++) {
        threads[i] = CreateThread(NULL, 0, thread_func, (LPVOID)(intptr_t)i, 0, NULL);
        if (threads[i] == NULL) {
            printf("CreateThread failed for worker %d\n", i);
            return 1;
        }
    }

    DWORD wait_result = WaitForMultipleObjects(4, threads, TRUE, INFINITE);
    printf("Wait result: %lu\n", (unsigned long)wait_result);
    printf("All threads done\n");
    return 0;
}
