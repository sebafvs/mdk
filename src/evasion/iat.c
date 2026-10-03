// MDK
// docs    : https://sebafvs.com/mdk/iat
// author  : @sebafvs

#include <windows.h>
#include "mdk/evasion.h"

static int _compile_time_seed(void) {
    return '0' * -40271 +
        __TIME__[7] * 1    +
        __TIME__[6] * 10   +
        __TIME__[4] * 60   +
        __TIME__[3] * 600  +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
}

VOID mdk_iat_camouflage(void) {
    int* seed = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
    if (!seed) { return; }
    *seed = _compile_time_seed() % 0xFF;

    if (*seed > 350) {
        unsigned __int64 i = (unsigned __int64)MessageBoxA(NULL, NULL, NULL, 0);
        i = GetLastError();
        i = SetCriticalSectionSpinCount(NULL, 0);
        i = GetWindowContextHelpId(NULL);
        i = GetWindowLongPtrW(NULL, 0);
        i = RegisterClassW(NULL);
        i = IsWindowVisible(NULL);
        i = ConvertDefaultLocale(0);
        i = MultiByteToWideChar(0, 0, NULL, 0, NULL, 0);
        i = IsDialogMessageW(NULL, NULL);
        (void)i;
    }

    HeapFree(GetProcessHeap(), 0, seed);
}
