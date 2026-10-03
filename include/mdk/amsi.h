// MDK
// docs    : https://sebafvs.com/mdk/amsi
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"
#include "hwbp.h"


MDK_RESULT mdk_amsi_bypass_install    (IN MDK_DRX drx, IN DWORD thread_id);
MDK_RESULT mdk_amsi_bypass_remove     (void);
LONG       mdk_amsi_bypass_hits       (void);
MDK_RESULT mdk_amsi_scan_buffer_addr  (OUT PVOID* address);
