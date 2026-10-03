// MDK
// docs    : https://sebafvs.com/mdk/hwbp
// author  : @sebafvs

#include <windows.h>
#include "mdk/result.h"
#include "mdk/thread.h"
#include "mdk/hwbp.h"
#include "mdk/nt.h"

// --- Internal types + globals ---

typedef struct _MDK_HWBP_DESCRIPTOR {
    PVOID                         address;
    MDK_DRX                       drx;
    DWORD                         thread_id;
    MDK_HWBP_DETOUR               detour;
    struct _MDK_HWBP_DESCRIPTOR*  next;
    struct _MDK_HWBP_DESCRIPTOR*  prev;
} MDK_HWBP_DESCRIPTOR;

static PVOID                _g_veh_handle          = NULL;
static MDK_HWBP_DESCRIPTOR* _g_head                = NULL;
static CRITICAL_SECTION     _g_lock                = { 0 };
static BOOL                 _g_ready               = FALSE;
static PVOID                _g_nt_create_thread_ex = NULL;

__attribute__((section(".text"))) static const unsigned char _ret_gadget[] = { 0xC3 };

// --- Forward declarations (private) ---

static MDK_RESULT           _hwbp_set_dr           (IN PVOID address, IN MDK_DRX drx, IN BOOL enable, IN DWORD thread_id);
static MDK_RESULT           _hwbp_snapshot_install (IN PVOID address, IN MDK_DRX drx, IN BOOL enable, IN DWORD thread_id);
static LONG WINAPI          _veh_dispatcher        (PEXCEPTION_POINTERS info);
static MDK_HWBP_DESCRIPTOR* _desc_find             (IN PVOID address, IN DWORD thread_id);
static void                 _desc_unlink           (IN MDK_HWBP_DESCRIPTOR* node);

// --- DR register write (per-thread) ---

static ULONG_PTR _set_dr7_bits(IN ULONG_PTR current, IN int start_bit, IN int nmbr_bits, IN ULONG_PTR new_value) {
    ULONG_PTR mask = (1ULL << nmbr_bits) - 1ULL;
    return (current & ~(mask << start_bit)) | (new_value << start_bit);
}

static MDK_RESULT _hwbp_set_dr(IN PVOID address, IN MDK_DRX drx, IN BOOL enable, IN DWORD thread_id) {

    HANDLE     thread_handle = NULL;
    BOOL       own_handle    = FALSE;
    MDK_RESULT r             = { 0 };

    if (thread_id == GetCurrentThreadId()) {
        thread_handle = (HANDLE)(LONG_PTR)-2;
    } else {
        r = mdk_open_thread(thread_id,
                            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                            &thread_handle);
        if (MDK_FAIL(r)) {
            return r;
        }
        own_handle = TRUE;
    }

    CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    r = mdk_get_context(thread_handle, &ctx);
    if (MDK_FAIL(r)) {
        if (own_handle) { mdk_close_thread(thread_handle); }
        return r;
    }

    ULONG_PTR new_dr = enable ? (ULONG_PTR)address : 0ULL;

    switch (drx) {
        case MDK_DR0: { ctx.Dr0 = new_dr; break; }
        case MDK_DR1: { ctx.Dr1 = new_dr; break; }
        case MDK_DR2: { ctx.Dr2 = new_dr; break; }
        case MDK_DR3: { ctx.Dr3 = new_dr; break; }
        default: {
            if (own_handle) { mdk_close_thread(thread_handle); }
            return MDK_MAKE_FAIL("_hwbp_set_dr:drx", MDK_STATUS_INVALID_PARAMETER);
        }
    }

    ctx.Dr7 = _set_dr7_bits(ctx.Dr7, drx * 2, 1, enable ? 1ULL : 0ULL);

    r = mdk_set_context(thread_handle, &ctx);

    if (own_handle) { mdk_close_thread(thread_handle); }
    return r;
}

// --- Descriptor list helpers (caller must hold _g_lock) ---

static MDK_HWBP_DESCRIPTOR* _desc_find(IN PVOID address, IN DWORD thread_id) {

    MDK_HWBP_DESCRIPTOR* cursor = _g_head;

    while (cursor != NULL) {
        BOOL address_match = (cursor->address == address);
        BOOL thread_match  = (cursor->thread_id == MDK_HWBP_ALL_THREADS) || (cursor->thread_id == thread_id);
        if (address_match && thread_match) {
            return cursor;
        }
        cursor = cursor->next;
    }

    return NULL;
}

static void _desc_unlink(IN MDK_HWBP_DESCRIPTOR* node) {

    if (node->prev != NULL) {
        node->prev->next = node->next;
    } else {
        _g_head = node->next;
    }

    if (node->next != NULL) {
        node->next->prev = node->prev;
    }
}

// --- VEH dispatcher ---

// Match under lock, invoke detour + flip DR outside lock. Keeps critical section short.
static LONG WINAPI _veh_dispatcher(PEXCEPTION_POINTERS info) {

    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    PVOID rip = info->ExceptionRecord->ExceptionAddress;
    DWORD tid = GetCurrentThreadId();

    MDK_HWBP_DETOUR detour  = NULL;
    MDK_DRX         drx     = MDK_DR0;
    BOOL            matched = FALSE;

    EnterCriticalSection(&_g_lock);
    MDK_HWBP_DESCRIPTOR* found = _desc_find(rip, tid);
    if (found != NULL) {
        detour  = found->detour;
        drx     = found->drx;
        matched = TRUE;
    }
    LeaveCriticalSection(&_g_lock);

    if (!matched) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    _hwbp_set_dr(rip, drx, FALSE, tid);
    detour(info->ContextRecord);
    _hwbp_set_dr(rip, drx, TRUE,  tid);

    return EXCEPTION_CONTINUE_EXECUTION;
}

// --- Snapshot install (multi-thread fanout) ----

static MDK_RESULT _hwbp_snapshot_install(IN PVOID address, IN MDK_DRX drx, IN BOOL enable, IN DWORD thread_id) {

    // Single-thread case: no enumeration needed, pass through.
    if (thread_id != MDK_HWBP_ALL_THREADS) {
        return _hwbp_set_dr(address, drx, enable, thread_id);
    }

    MDK_THREAD_LIST list = { 0 };
    MDK_RESULT r = mdk_enum_threads(GetCurrentProcessId(), &list);
    if (MDK_FAIL(r)) {
        return r;
    }

    MDK_RESULT first_fail = MDK_MAKE_OK();

    for (DWORD i = 0; i < list.count; i++) {
        DWORD tid = list.entries[i].tid;
        if (tid == 0) { continue; }

        MDK_RESULT rr = _hwbp_set_dr(address, drx, enable, tid);
        if (MDK_FAIL(rr) && MDK_OK(first_fail)) {
            first_fail = rr;
        }
    }

    mdk_free_thread_list(&list);
    return first_fail;
}

// --- New-thread coverage (NtCreateThreadEx detour + timer callback) ----

#define _THREAD_CREATE_FLAGS_CREATE_SUSPENDED  0x00000001

static VOID CALLBACK _timed_hook_callback(PVOID lp_parameter, BOOLEAN timer_or_wait_fired) {
    (void)timer_or_wait_fired;

    volatile HANDLE* p_new_thread = (volatile HANDLE*)lp_parameter;

    HANDLE new_thread = NULL;
    for (int i = 0; i < 10000; i++) {
        new_thread = *p_new_thread;
        if (new_thread != NULL && new_thread != INVALID_HANDLE_VALUE) { break; }
        SwitchToThread();
    }
    if (new_thread == NULL || new_thread == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD new_tid = GetThreadId(new_thread);
    if (new_tid == 0) {
        // Cannot resolve TID; still resume so the caller does not hang.
        ResumeThread(new_thread);
        return;
    }

    EnterCriticalSection(&_g_lock);

    int installed = 0;
    for (MDK_HWBP_DESCRIPTOR* cursor = _g_head; cursor != NULL; cursor = cursor->next) {
        if (cursor->thread_id != MDK_HWBP_ALL_THREADS) { continue; }

        _hwbp_set_dr(cursor->address, cursor->drx, TRUE, new_tid);
        installed++;
        if (installed >= 4) { break; }
    }

    LeaveCriticalSection(&_g_lock);

    // Release the new thread with the DRs armed.
    ResumeThread(new_thread);
}

static void _nt_create_thread_ex_detour(PCONTEXT ctx) {

    // Arg 1: PHANDLE ThreadHandle, the caller's output slot.
    PVOID p_thread_out = (PVOID)mdk_hwbp_get_arg(ctx, 1);

    ULONG_PTR flags = mdk_hwbp_get_arg(ctx, 7);
    flags |= _THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
    mdk_hwbp_set_arg(ctx, 7, flags);

    HANDLE timer = NULL;
    CreateTimerQueueTimer(&timer, NULL,
                          (WAITORTIMERCALLBACK)_timed_hook_callback,
                          p_thread_out,
                          0, 0, 0);

    mdk_hwbp_continue(ctx);
}

// --- Public API - Detour-callable helpers ------------------------------

// x64 fastcall at function entry: rcx/rdx/r8/r9, then [rsp+0x28+8*(N-5)] for arg N>=5.
static ULONG_PTR* _arg_slot(PCONTEXT ctx, DWORD index) {
    switch (index) {
        case 1:  return (ULONG_PTR*)&ctx->Rcx;
        case 2:  return (ULONG_PTR*)&ctx->Rdx;
        case 3:  return (ULONG_PTR*)&ctx->R8;
        case 4:  return (ULONG_PTR*)&ctx->R9;
        default: return (ULONG_PTR*)(ctx->Rsp + (index * sizeof(PVOID)));
    }
}

ULONG_PTR mdk_hwbp_get_arg(IN PCONTEXT ctx, IN DWORD index) {
    return *_arg_slot(ctx, index);
}

void mdk_hwbp_set_arg(IN PCONTEXT ctx, IN DWORD index, IN ULONG_PTR value) {
    *_arg_slot(ctx, index) = value;
}

void mdk_hwbp_return_value(IN PCONTEXT ctx, IN ULONG_PTR value) {
    ctx->Rax = value;
}

void mdk_hwbp_block_real(IN PCONTEXT ctx) {
    ctx->Rip = (ULONG_PTR)&_ret_gadget[0];
}

void mdk_hwbp_continue(IN PCONTEXT ctx) {
    ctx->EFlags |= (1UL << 16);
}

// --- Public API - Lifecycle ----

MDK_RESULT mdk_hwbp_init(void) {

    if (_g_ready) {
        return MDK_MAKE_OK();
    }

    InitializeCriticalSection(&_g_lock);

    _g_veh_handle = AddVectoredExceptionHandler(1, _veh_dispatcher);
    if (_g_veh_handle == NULL) {
        DeleteCriticalSection(&_g_lock);
        return MDK_MAKE_FAIL("mdk_hwbp_init:AddVectoredExceptionHandler", MDK_STATUS_UNSUCCESSFUL);
    }

    _g_ready = TRUE;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_hwbp_cleanup(void) {

    if (!_g_ready) {
        return MDK_MAKE_OK();
    }

    EnterCriticalSection(&_g_lock);

    MDK_HWBP_DESCRIPTOR* cursor = _g_head;
    while (cursor != NULL) {
        MDK_HWBP_DESCRIPTOR* next = cursor->next;
        _hwbp_snapshot_install(cursor->address, cursor->drx, FALSE, cursor->thread_id);
        HeapFree(GetProcessHeap(), 0, cursor);
        cursor = next;
    }
    _g_head = NULL;

    LeaveCriticalSection(&_g_lock);

    if (_g_veh_handle != NULL) {
        RemoveVectoredExceptionHandler(_g_veh_handle);
        _g_veh_handle = NULL;
    }

    DeleteCriticalSection(&_g_lock);
    _g_ready = FALSE;

    return MDK_MAKE_OK();
}

// --- Public API - Install / Remove ---

MDK_RESULT mdk_hwbp_install(IN PVOID address, IN MDK_DRX drx, IN MDK_HWBP_DETOUR detour, IN DWORD thread_id) {

    if (!_g_ready) {
        return MDK_MAKE_FAIL("mdk_hwbp_install", MDK_STATUS_UNSUCCESSFUL);
    }

    MDK_HWBP_DESCRIPTOR* node = (MDK_HWBP_DESCRIPTOR*)HeapAlloc(GetProcessHeap(),
                                                               HEAP_ZERO_MEMORY,
                                                               sizeof(MDK_HWBP_DESCRIPTOR));
    if (node == NULL) {
        return MDK_MAKE_FAIL("mdk_hwbp_install:HeapAlloc", MDK_STATUS_NO_MEMORY);
    }

    node->address   = address;
    node->drx       = drx;
    node->thread_id = thread_id;
    node->detour    = detour;

    EnterCriticalSection(&_g_lock);
    node->next = _g_head;
    node->prev = NULL;
    if (_g_head != NULL) {
        _g_head->prev = node;
    }
    _g_head = node;
    LeaveCriticalSection(&_g_lock);

    MDK_RESULT r = _hwbp_snapshot_install(address, drx, TRUE, thread_id);
    if (MDK_FAIL(r)) {
        EnterCriticalSection(&_g_lock);
        _desc_unlink(node);
        LeaveCriticalSection(&_g_lock);
        HeapFree(GetProcessHeap(), 0, node);
        return r;
    }

    return MDK_MAKE_OK();
}

MDK_RESULT mdk_hwbp_remove(IN PVOID address, IN DWORD thread_id) {

    if (!_g_ready) {
        return MDK_MAKE_FAIL("mdk_hwbp_remove", MDK_STATUS_UNSUCCESSFUL);
    }

    MDK_DRX drx     = MDK_DR0;
    BOOL    matched = FALSE;

    EnterCriticalSection(&_g_lock);
    MDK_HWBP_DESCRIPTOR* found = _desc_find(address, thread_id);
    if (found != NULL) {
        drx     = found->drx;
        matched = TRUE;
        _desc_unlink(found);
        HeapFree(GetProcessHeap(), 0, found);
    }
    LeaveCriticalSection(&_g_lock);

    if (!matched) {
        return MDK_MAKE_FAIL("mdk_hwbp_remove", MDK_STATUS_NOT_FOUND);
    }

    return _hwbp_snapshot_install(address, drx, FALSE, thread_id);
}

// --- Public API - New-thread coverage ---

MDK_RESULT mdk_hwbp_hook_new_threads(IN MDK_DRX drx) {

    if (!_g_ready) {
        return MDK_MAKE_FAIL("mdk_hwbp_hook_new_threads", MDK_STATUS_UNSUCCESSFUL);
    }

    if (_g_nt_create_thread_ex == NULL) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == NULL) {
            return MDK_MAKE_FAIL("mdk_hwbp_hook_new_threads:ntdll", MDK_STATUS_DLL_NOT_FOUND);
        }
        _g_nt_create_thread_ex = (PVOID)GetProcAddress(ntdll, "NtCreateThreadEx");
        if (_g_nt_create_thread_ex == NULL) {
            return MDK_MAKE_FAIL("mdk_hwbp_hook_new_threads:GetProcAddress", MDK_STATUS_ENTRYPOINT_NOT_FOUND);
        }
    }

    return mdk_hwbp_install(_g_nt_create_thread_ex, drx, _nt_create_thread_ex_detour, MDK_HWBP_ALL_THREADS);
}

MDK_RESULT mdk_hwbp_unhook_new_threads(void) {

    if (!_g_ready) {
        return MDK_MAKE_FAIL("mdk_hwbp_unhook_new_threads", MDK_STATUS_UNSUCCESSFUL);
    }
    if (_g_nt_create_thread_ex == NULL) {
        return MDK_MAKE_FAIL("mdk_hwbp_unhook_new_threads:not-installed", MDK_STATUS_NOT_FOUND);
    }

    return mdk_hwbp_remove(_g_nt_create_thread_ex, MDK_HWBP_ALL_THREADS);
}
