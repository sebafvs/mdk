// MDK
// docs    : https://sebafvs.com/mdk/etw
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"
#include "hwbp.h"


MDK_RESULT mdk_etw_bypass_install    (IN MDK_DRX drx, IN DWORD thread_id);
MDK_RESULT mdk_etw_bypass_remove     (void);
LONG       mdk_etw_bypass_hits       (void);
MDK_RESULT mdk_etw_event_write_addr  (OUT PVOID* address);
