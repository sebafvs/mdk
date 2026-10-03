// MDK
// docs    : https://sebafvs.com/mdk/evasion
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"


MDK_RESULT mdk_dfr_resolve(IN DWORD module_hash, IN DWORD func_hash, OUT PVOID* address);
MDK_RESULT mdk_dfr_resolve_name(IN const char* module, IN const char* func, OUT PVOID* address);

VOID mdk_iat_camouflage(void);
