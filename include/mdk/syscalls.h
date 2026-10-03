// MDK
// docs    : https://sebafvs.com/mdk/syscalls
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"


MDK_RESULT mdk_sc_init       (void);
MDK_RESULT mdk_sc_resolve    (IN DWORD zw_hash, OUT PVOID* stub);
DWORD      mdk_sc_get_ssn    (IN DWORD zw_hash);
PVOID      mdk_sc_get_gadget (IN DWORD zw_hash);
MDK_RESULT mdk_sc_free       (void);
