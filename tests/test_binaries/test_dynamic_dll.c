#include <stdio.h>
#include <windows.h>

typedef int (__cdecl *answer_fn)(void);

int main(void) {
    HMODULE module = LoadLibraryA("acceptance_plugin.dll");
    if (!module) return 40;
    answer_fn answer = (answer_fn)GetProcAddress(module, "acceptance_answer");
    if (!answer) return 41;
    int value = answer();
    printf("answer=%d\n", value);
    FreeLibrary(module);
    return value == 42 ? 0 : 42;
}
