// MDK
// docs    : https://sebafvs.com/mdk/env
// author  : @sebafvs

#include <windows.h>
#include "mdk/process.h"
#include "mdk/nt.h"
#include "mdk/hashes.h"
#include "mdk/evasion.h"

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_elevation
typedef struct { ULONG TokenIsElevated; } MDK_TOKEN_ELEVATION;

// function pointer types

typedef NTSTATUS(NTAPI* pfnRtlGetVersion)(OSVERSIONINFOW* VersionInformation);

typedef NTSTATUS(NTAPI* pfnNtOpenProcessToken)(
    HANDLE      ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE     TokenHandle);

typedef NTSTATUS(NTAPI* pfnNtQueryInformationToken)(
    HANDLE  TokenHandle,
    ULONG   TokenInformationClass,
    PVOID   TokenInformation,
    ULONG   TokenInformationLength,
    PULONG  ReturnLength);

typedef NTSTATUS(NTAPI* pfnNtClose)(HANDLE Handle);

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength);

// static state

static pfnRtlGetVersion             _RtlGetVersion;
static pfnNtOpenProcessToken        _NtOpenProcTok;
static pfnNtQueryInformationToken   _NtQIT;
static pfnNtClose                   _NtClose;
static pfnNtQueryInformationProcess _NtQIP;
static BOOL                         _ready;

// init

static MDK_RESULT _init(void) {
    if (_ready) { return MDK_MAKE_OK(); }
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, RtlGetVersion_H,             (PVOID*)&_RtlGetVersion));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtOpenProcessToken_H,        (PVOID*)&_NtOpenProcTok));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtQueryInformationToken_H,   (PVOID*)&_NtQIT));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtClose_H,                   (PVOID*)&_NtClose));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtQueryInformationProcess_H, (PVOID*)&_NtQIP));
    _ready = TRUE;
    return MDK_MAKE_OK();
}

// environment

MDK_RESULT mdk_get_os_version(OUT OSVERSIONINFOW* info) {
    MDK_CHECK(_init());
    info->dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);

    NTSTATUS status = _RtlGetVersion(info);
    return status ? MDK_MAKE_FAIL("RtlGetVersion", status) : MDK_MAKE_OK();
}

MDK_RESULT mdk_is_elevated(OUT BOOL* result) {
    MDK_CHECK(_init());
    HANDLE token = NULL;

    // (HANDLE)-1 is the current process pseudo-handle.
    NTSTATUS status = _NtOpenProcTok((HANDLE)-1, TOKEN_QUERY, &token);
    if (status) { return MDK_MAKE_FAIL("NtOpenProcessToken", status); }

    MDK_TOKEN_ELEVATION token_elevation = { 0 };
    ULONG               return_length   = 0;

    status = _NtQIT(token, 20 /* TokenElevation */, &token_elevation, sizeof(token_elevation), &return_length);
    _NtClose(token);

    if (status) { return MDK_MAKE_FAIL("NtQueryInformationToken", status); }

    *result = (BOOL)token_elevation.TokenIsElevated;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_get_integrity_level(IN HANDLE process, OUT DWORD* level) {
    MDK_CHECK(_init());
    HANDLE token = NULL;

    NTSTATUS status = _NtOpenProcTok(process, TOKEN_QUERY, &token);
    if (status) { return MDK_MAKE_FAIL("NtOpenProcessToken", status); }

    // First call: get required buffer size.
    ULONG required_size = 0;
    _NtQIT(token, 25 /* TokenIntegrityLevel */, NULL, 0, &required_size);
    if (!required_size) {
        _NtClose(token);
        return MDK_MAKE_FAIL("NtQueryInformationToken:size", MDK_STATUS_INVALID_PARAMETER);
    }

    BYTE* token_info_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, required_size);
    if (!token_info_buffer) {
        _NtClose(token);
        return MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY);
    }

    ULONG return_length = 0;
    status = _NtQIT(token, 25, token_info_buffer, required_size, &return_length);
    _NtClose(token);

    if (status) {
        HeapFree(GetProcessHeap(), 0, token_info_buffer);
        return MDK_MAKE_FAIL("NtQueryInformationToken", status);
    }

    BYTE* sid_pointer         = *(BYTE**)token_info_buffer;
    BYTE  sub_authority_count = sid_pointer[1];

    if (!sub_authority_count) {
        HeapFree(GetProcessHeap(), 0, token_info_buffer);
        return MDK_MAKE_FAIL("mdk_get_integrity_level:no_subauth", MDK_STATUS_INVALID_PARAMETER);
    }

    *level = *(DWORD*)(sid_pointer + 8 + (sub_authority_count - 1) * 4);

    HeapFree(GetProcessHeap(), 0, token_info_buffer);
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_get_session_id(IN HANDLE process, OUT DWORD* session_id) {
    MDK_CHECK(_init());
    DWORD session_value = 0;
    ULONG return_length = 0;

    NTSTATUS status = _NtQIP(process, 24 /* ProcessSessionInformation */, &session_value, sizeof(DWORD), &return_length);
    if (status) { return MDK_MAKE_FAIL("NtQueryInformationProcess", status); }

    *session_id = session_value;
    return MDK_MAKE_OK();
}
