// MDK
// docs    : https://sebafvs.com/mdk/process
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"
#include "nt.h"


// https://github.com/winsiderss/phnt/blob/master/ntexapi.h
typedef struct {
    DWORD pid;
    DWORD ppid;
    DWORD thread_count;
    WCHAR name[260];
} MDK_PROCESS_ENTRY;

typedef struct {
    MDK_PROCESS_ENTRY* entries;
    DWORD              count;
} MDK_PROCESS_LIST;


// --- Enumeration ---

MDK_RESULT mdk_enum_processes    (OUT MDK_PROCESS_LIST* list);
MDK_RESULT mdk_find_by_name      (IN MDK_PROCESS_LIST* list, IN const WCHAR* name, OUT MDK_PROCESS_ENTRY* entry);
MDK_RESULT mdk_find_by_pid       (IN MDK_PROCESS_LIST* list, IN DWORD pid, OUT MDK_PROCESS_ENTRY* entry);
MDK_RESULT mdk_find_by_window    (IN const WCHAR* window_name, OUT MDK_PROCESS_ENTRY* entry);
void       mdk_free_process_list (IN MDK_PROCESS_LIST* list);


// --- Handle management ---

MDK_RESULT mdk_open_process  (IN DWORD pid, IN DWORD access, OUT HANDLE* process);
MDK_RESULT mdk_close_handle  (IN HANDLE handle);
MDK_RESULT mdk_dup_handle    (IN HANDLE src_proc, IN HANDLE src, IN HANDLE dst_proc, OUT HANDLE* dst, IN DWORD access);


// --- Inspection ---

MDK_RESULT mdk_get_peb_address     (IN HANDLE process, OUT PVOID* address);
MDK_RESULT mdk_read_peb            (IN HANDLE process, OUT MDK_PEB* peb);
MDK_RESULT mdk_get_base_address    (IN HANDLE process, OUT PVOID* address);
MDK_RESULT mdk_is_wow64            (IN HANDLE process, OUT BOOL* result);
MDK_RESULT mdk_get_integrity_level (IN HANDLE process, OUT DWORD* level);
MDK_RESULT mdk_resolve_export      (IN HANDLE process, IN PVOID remote_base, IN const char* func_name, OUT PVOID* address);


// --- Environment ---

MDK_RESULT mdk_get_os_version (OUT OSVERSIONINFOW* info);
MDK_RESULT mdk_is_elevated    (OUT BOOL* result);
MDK_RESULT mdk_get_session_id (IN HANDLE process, OUT DWORD* session_id);
