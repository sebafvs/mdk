// MDK
// docs    : https://sebafvs.com/mdk/hwbp
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"


typedef enum {
    MDK_DR0 = 0,
    MDK_DR1 = 1,
    MDK_DR2 = 2,
    MDK_DR3 = 3
} MDK_DRX;

typedef void (*MDK_HWBP_DETOUR)(PCONTEXT ctx);

#define MDK_HWBP_ALL_THREADS 0


// --- Lifecycle ---

MDK_RESULT mdk_hwbp_init    (void);
MDK_RESULT mdk_hwbp_cleanup (void);


// --- Install / Remove ---

MDK_RESULT mdk_hwbp_install (IN PVOID address, IN MDK_DRX drx, IN MDK_HWBP_DETOUR detour, IN DWORD thread_id);
MDK_RESULT mdk_hwbp_remove  (IN PVOID address, IN DWORD thread_id);


// --- New-thread coverage ---

MDK_RESULT mdk_hwbp_hook_new_threads   (IN MDK_DRX drx);
MDK_RESULT mdk_hwbp_unhook_new_threads (void);


// --- Detour-callable helpers ---

ULONG_PTR mdk_hwbp_get_arg      (IN PCONTEXT ctx, IN DWORD index);
void      mdk_hwbp_set_arg      (IN PCONTEXT ctx, IN DWORD index, IN ULONG_PTR value);
void      mdk_hwbp_return_value (IN PCONTEXT ctx, IN ULONG_PTR value);
void      mdk_hwbp_block_real   (IN PCONTEXT ctx);
void      mdk_hwbp_continue     (IN PCONTEXT ctx);
