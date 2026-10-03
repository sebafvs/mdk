// MDK
// docs    : https://sebafvs.com/mdk/enum_process.c
// author  : @sebafvs

#include <windows.h>
#include "mdk/process.h"
#include "mdk/nt.h"
#include "mdk/hashes.h"
#include "mdk/evasion.h"
#include "mdk/utils.h"

// function pointer types

typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength);

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

MDK_RESULT mdk_enum_processes(OUT MDK_PROCESS_LIST* list) {
    MDK_CHECK(_init());
    // First call: get required buffer size (always fails with STATUS_INFO_LENGTH_MISMATCH).
    ULONG required_size = 0;
    _NtQSI(5, NULL, 0, &required_size);
    required_size += 4096;

    MDK_SYS_PROC* system_info_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, required_size);
    if (!system_info_buffer) { return MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY); }

    ULONG    return_length = 0;
    NTSTATUS status        = _NtQSI(5, system_info_buffer, required_size, &return_length);
    if (status) {
        HeapFree(GetProcessHeap(), 0, system_info_buffer);
        return MDK_MAKE_FAIL("NtQuerySystemInformation", status);
    }

    DWORD         process_count = 0;
    MDK_SYS_PROC* current_entry = system_info_buffer;

    while (1) {
        process_count++;
        if (!current_entry->NextEntryOffset) { break; }
        current_entry = (MDK_SYS_PROC*)((BYTE*)current_entry + current_entry->NextEntryOffset);
    }

    MDK_PROCESS_ENTRY* entries = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, process_count * sizeof(MDK_PROCESS_ENTRY));
    if (!entries) {
        HeapFree(GetProcessHeap(), 0, system_info_buffer);
        return MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY);
    }

    current_entry = system_info_buffer;

    for (DWORD i = 0; i < process_count; i++) {
        entries[i].pid          = (DWORD)(ULONG_PTR)current_entry->UniqueProcessId;
        entries[i].ppid         = (DWORD)(ULONG_PTR)current_entry->InheritedFromUniqueProcessId;
        entries[i].thread_count = current_entry->NumberOfThreads;

        if (current_entry->ImageName.Buffer && current_entry->ImageName.Length) {
            DWORD name_char_count = current_entry->ImageName.Length / sizeof(WCHAR);
            if (name_char_count >= 260) { name_char_count = 259; }
            mdk_memcpy(entries[i].name, current_entry->ImageName.Buffer, name_char_count * sizeof(WCHAR));
            entries[i].name[name_char_count] = L'\0';
        }

        if (!current_entry->NextEntryOffset) { break; }
        current_entry = (MDK_SYS_PROC*)((BYTE*)current_entry + current_entry->NextEntryOffset);
    }

    HeapFree(GetProcessHeap(), 0, system_info_buffer);
    list->entries = entries;
    list->count   = process_count;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_find_by_name(IN MDK_PROCESS_LIST* list, IN const WCHAR* name, OUT MDK_PROCESS_ENTRY* entry) {
    for (DWORD i = 0; i < list->count; i++) {
        if (mdk_wcscmp(list->entries[i].name, name) == 0) {
            *entry = list->entries[i];
            return MDK_MAKE_OK();
        }
    }

    return MDK_MAKE_FAIL("mdk_find_by_name", MDK_STATUS_NOT_FOUND);
}

MDK_RESULT mdk_find_by_pid(IN MDK_PROCESS_LIST* list, IN DWORD pid, OUT MDK_PROCESS_ENTRY* entry) {
    for (DWORD i = 0; i < list->count; i++) {
        if (list->entries[i].pid == pid) {
            *entry = list->entries[i];
            return MDK_MAKE_OK();
        }
    }

    return MDK_MAKE_FAIL("mdk_find_by_pid", MDK_STATUS_NOT_FOUND);
}

typedef HWND  (WINAPI* pfnFindWindowW)(LPCWSTR, LPCWSTR);
typedef DWORD (WINAPI* pfnGetWindowThreadProcessId)(HWND, PDWORD);

MDK_RESULT mdk_find_by_window(IN const WCHAR* window_name, OUT MDK_PROCESS_ENTRY* entry) {
    static pfnFindWindowW              _FindWindowW;
    static pfnGetWindowThreadProcessId _GetWindowThreadProcessId;
    static BOOL                        _w32_ready;

    if (!_w32_ready) {
        MDK_CHECK(mdk_dfr_resolve(USER32_H, FindWindowW_H,              (PVOID*)&_FindWindowW));
        MDK_CHECK(mdk_dfr_resolve(USER32_H, GetWindowThreadProcessId_H, (PVOID*)&_GetWindowThreadProcessId));
        _w32_ready = TRUE;
    }

    HWND  window_handle = _FindWindowW(NULL, window_name);
    if (!window_handle) { return MDK_MAKE_FAIL("FindWindowW", MDK_STATUS_NOT_FOUND); }

    DWORD window_pid = 0;
    _GetWindowThreadProcessId(window_handle, &window_pid);
    if (!window_pid) { return MDK_MAKE_FAIL("GetWindowThreadProcessId", MDK_STATUS_NOT_FOUND); }

    MDK_PROCESS_LIST process_list = { 0 };
    MDK_CHECK(mdk_enum_processes(&process_list));

    MDK_RESULT result = mdk_find_by_pid(&process_list, window_pid, entry);
    mdk_free_process_list(&process_list);
    return result;
}

void mdk_free_process_list(IN MDK_PROCESS_LIST* list) {
    if (list->entries) { HeapFree(GetProcessHeap(), 0, list->entries); }
    list->entries = NULL;
    list->count   = 0;
}
