// MDK
// docs    : https://sebafvs.com/mdk/enum_thread.c
// author  : @sebafvs

#include <windows.h>
#include "mdk/thread.h"
#include "mdk/evasion.h"
#include "mdk/nt.h"
#include "mdk/hashes.h"

// internal types

// https://github.com/winsiderss/phnt/blob/master/ntexapi.h
typedef struct {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    ULONG         _r0;          // explicit pad, keeps StartAddress 8-byte aligned
    PVOID         StartAddress;
    MDK_CLIENT_ID ClientId;     // 2 HANDLEs = 16 bytes
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    ULONG         WaitReason;
    ULONG         _r1;          // explicit tail pad, sizeof == 80
} _MDK_SYS_THREAD;

_Static_assert(sizeof(_MDK_SYS_THREAD) == 80,  "SYSTEM_THREAD_INFORMATION size mismatch");
_Static_assert(sizeof(MDK_SYS_PROC)    == 256, "SYSTEM_PROCESS_INFORMATION size mismatch");

// function pointer types

typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(ULONG Class, PVOID Buffer, ULONG Length, PULONG ReturnLength);

// static state

static pfnNtQuerySystemInformation _NtQSI;
static BOOL                        _ready;

// init

static MDK_RESULT _init(void) {
    if (_ready) { return MDK_MAKE_OK(); }
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtQuerySystemInformation_H, (PVOID*)&_NtQSI));
    _ready = TRUE;
    return MDK_MAKE_OK();
}

// enumeration

MDK_RESULT mdk_enum_threads(IN DWORD pid, OUT MDK_THREAD_LIST* list) {
    MDK_CHECK(_init());
    list->entries = NULL;
    list->count   = 0;

    ULONG required_size = 0;
    _NtQSI(5, NULL, 0, &required_size);
    required_size += 0x1000;

    PVOID system_info_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, required_size);
    if (!system_info_buffer) { return MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY); }

    NTSTATUS status = _NtQSI(5, system_info_buffer, required_size, NULL);
    if (status) {
        HeapFree(GetProcessHeap(), 0, system_info_buffer);
        return MDK_MAKE_FAIL("NtQuerySystemInformation", status);
    }

    MDK_SYS_PROC* current_process = (MDK_SYS_PROC*)system_info_buffer;
    MDK_SYS_PROC* target_process  = NULL;

    while (1) {
        if ((DWORD)(ULONG_PTR)current_process->UniqueProcessId == pid) {
            target_process = current_process;
            break;
        }
        if (!current_process->NextEntryOffset) { break; }
        current_process = (MDK_SYS_PROC*)((BYTE*)current_process + current_process->NextEntryOffset);
    }

    if (!target_process || !target_process->NumberOfThreads) {
        HeapFree(GetProcessHeap(), 0, system_info_buffer);
        return MDK_MAKE_FAIL("mdk_enum_threads:pid_not_found", MDK_STATUS_NOT_FOUND);
    }

    DWORD             thread_count = target_process->NumberOfThreads;
    MDK_THREAD_ENTRY* entries      = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, thread_count * sizeof(MDK_THREAD_ENTRY));

    if (!entries) {
        HeapFree(GetProcessHeap(), 0, system_info_buffer);
        return MDK_MAKE_FAIL("HeapAlloc:entries", MDK_STATUS_NO_MEMORY);
    }

    // Thread entries immediately follow the process info block.
    _MDK_SYS_THREAD* threads = (_MDK_SYS_THREAD*)(target_process + 1);

    for (DWORD i = 0; i < thread_count; i++) {
        entries[i].tid         = (DWORD)(ULONG_PTR)threads[i].ClientId.UniqueThread;
        entries[i].owner_pid   = (DWORD)(ULONG_PTR)threads[i].ClientId.UniqueProcess;
        entries[i].wait_reason = threads[i].WaitReason;
        entries[i].create_time = threads[i].CreateTime.QuadPart;
    }

    HeapFree(GetProcessHeap(), 0, system_info_buffer);
    list->entries = entries;
    list->count   = thread_count;
    return MDK_MAKE_OK();
}

void mdk_free_thread_list(IN MDK_THREAD_LIST* list) {
    if (list->entries) { HeapFree(GetProcessHeap(), 0, list->entries); }
    list->entries = NULL;
    list->count   = 0;
}

// thread search

MDK_RESULT mdk_find_main_thread(IN MDK_THREAD_LIST* list, OUT MDK_THREAD_ENTRY* entry) {
    MDK_THREAD_ENTRY* earliest_thread = &list->entries[0];

    for (DWORD i = 1; i < list->count; i++) {
        if (list->entries[i].create_time < earliest_thread->create_time) {
            earliest_thread = &list->entries[i];
        }
    }

    *entry = *earliest_thread;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_find_alertable_thread(IN MDK_THREAD_LIST* list, OUT MDK_THREAD_ENTRY* entry) {
    // Prefer WrUserRequest(5), typical alertable wait state in user-mode threads.
    for (DWORD i = 0; i < list->count; i++) {
        if (list->entries[i].wait_reason == 5) {
            *entry = list->entries[i];
            return MDK_MAKE_OK();
        }
    }

    // Fallback: return first thread, caller decides whether to attempt APC.
    *entry = list->entries[0];
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_open_worker_thread(IN DWORD pid, IN DWORD access, OUT DWORD* tid, OUT HANDLE* thread) {
    MDK_THREAD_LIST  thread_list  = { 0 };
    MDK_THREAD_ENTRY main_thread  = { 0 };

    MDK_CHECK(mdk_enum_threads(pid, &thread_list));

    MDK_RESULT result = mdk_find_main_thread(&thread_list, &main_thread);
    if (MDK_FAIL(result)) {
        mdk_free_thread_list(&thread_list);
        return result;
    }

    result = MDK_MAKE_FAIL("mdk_open_worker_thread", MDK_STATUS_NOT_FOUND);

    for (DWORD i = 0; i < thread_list.count; i++) {
        if (thread_list.entries[i].tid == main_thread.tid) { continue; }

        result = mdk_open_thread(thread_list.entries[i].tid, access, thread);
        if (MDK_OK(result) && tid) { *tid = thread_list.entries[i].tid; }
        break;
    }

    mdk_free_thread_list(&thread_list);
    return result;
}
