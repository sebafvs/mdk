// MDK
// docs    : https://sebafvs.com/mdk/thread
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"


// https://github.com/winsiderss/phnt/blob/master/ntexapi.h
typedef struct {
    DWORD    tid;
    DWORD    owner_pid;
    DWORD    wait_reason;
    LONGLONG create_time;
} MDK_THREAD_ENTRY;

typedef struct {
    MDK_THREAD_ENTRY* entries;
    DWORD             count;
} MDK_THREAD_LIST;


// --- Enumeration ---

MDK_RESULT mdk_enum_threads          (IN DWORD pid, OUT MDK_THREAD_LIST* list);
MDK_RESULT mdk_find_alertable_thread (IN MDK_THREAD_LIST* list, OUT MDK_THREAD_ENTRY* entry);
MDK_RESULT mdk_open_worker_thread    (IN DWORD pid, IN DWORD access, OUT DWORD* tid, OUT HANDLE* thread);
MDK_RESULT mdk_find_main_thread      (IN MDK_THREAD_LIST* list, OUT MDK_THREAD_ENTRY* entry);
void       mdk_free_thread_list      (IN MDK_THREAD_LIST* list);


// --- Handle management ---

MDK_RESULT mdk_open_thread  (IN DWORD tid, IN DWORD access, OUT HANDLE* thread);
MDK_RESULT mdk_close_thread (IN HANDLE thread);


// --- Control ---

MDK_RESULT mdk_suspend_thread  (IN HANDLE thread);
MDK_RESULT mdk_resume_thread   (IN HANDLE thread);
MDK_RESULT mdk_suspend_process (IN HANDLE process);
MDK_RESULT mdk_resume_process  (IN HANDLE process);


// --- Context manipulation ---

MDK_RESULT mdk_get_context (IN HANDLE thread, IN OUT CONTEXT* ctx);
MDK_RESULT mdk_set_context (IN HANDLE thread, IN CONTEXT* ctx);
MDK_RESULT mdk_get_rip     (IN HANDLE thread, OUT PVOID* rip);
MDK_RESULT mdk_set_rip     (IN HANDLE thread, IN PVOID rip);


// --- Creation ---

MDK_RESULT mdk_create_remote_thread (IN HANDLE process, IN PVOID start, IN PVOID param, IN DWORD flags, OUT HANDLE* thread);


// --- APC ---

MDK_RESULT mdk_queue_apc (IN HANDLE thread, IN PVOID apc_routine, IN PVOID arg);


// --- Utils ---

MDK_RESULT mdk_hijack_thread (IN HANDLE thread, IN PVOID address);
