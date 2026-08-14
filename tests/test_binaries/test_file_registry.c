#include <stdio.h>
#include <windows.h>

int main(void) {
    HANDLE file = CreateFileA("acceptance.txt", GENERIC_WRITE | GENERIC_READ, 0,
                              NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 10;

    const char payload[] = "file-ok";
    DWORD written = 0;
    if (!WriteFile(file, payload, sizeof(payload) - 1, &written, NULL)) return 11;
    CloseHandle(file);

    file = CreateFileA("ACCEPTANCE.TXT", GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 12;

    char buffer[16] = {0};
    DWORD read = 0;
    if (!ReadFile(file, buffer, sizeof(buffer) - 1, &read, NULL)) return 13;
    CloseHandle(file);
    printf("file=%.*s bytes=%lu\n", (int)read, buffer, (unsigned long)read);
    return (read == sizeof(payload) - 1) ? 0 : 14;
}
