#include <stdio.h>
#include <windows.h>

int main(void) {
    HKEY key = NULL;
    const char subkey[] = "Software\\TuxExeAcceptance";
    const char value_name[] = "Status";
    const char value[] = "registry-ok";
    DWORD disposition = 0;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, subkey, 0, NULL, 0, KEY_ALL_ACCESS,
                        NULL, &key, &disposition) != ERROR_SUCCESS) return 50;
    if (RegSetValueExA(key, value_name, 0, REG_SZ, (const BYTE *)value,
                       sizeof(value)) != ERROR_SUCCESS) return 51;

    char buffer[32] = {0};
    DWORD type = 0;
    DWORD size = sizeof(buffer);
    if (RegQueryValueExA(key, value_name, NULL, &type, (BYTE *)buffer, &size) != ERROR_SUCCESS)
        return 52;
    RegCloseKey(key);
    printf("registry=%s type=%lu\n", buffer, (unsigned long)type);
    return 0;
}
