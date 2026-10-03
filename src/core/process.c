// MDK
// docs    : https://sebafvs.com/mdk/process
// author  : @sebafvs

#include <windows.h>
#include "mdk/process.h"
#include "mdk/memory.h"
#include "mdk/nt.h"
#include "mdk/hashes.h"
#include "mdk/evasion.h"
#include "mdk/utils.h"

// internal types

// https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
typedef struct {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MDK_PROC_BASIC_INFO;

// function pointer types

typedef NTSTATUS(NTAPI* pfnNtOpenProcess)(
    PHANDLE        ProcessHandle,
    ACCESS_MASK    DesiredAccess,
    MDK_OBJ_ATTRS* ObjectAttributes,
    MDK_CLIENT_ID* ClientId);

typedef NTSTATUS(NTAPI* pfnNtClose)(HANDLE Handle);

typedef NTSTATUS(NTAPI* pfnNtDuplicateObject)(
    HANDLE      SourceProcessHandle,
    HANDLE      SourceHandle,
    HANDLE      TargetProcessHandle,
    PHANDLE     TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG       HandleAttributes,
    ULONG       Options);

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(NTAPI* pfnNtReadVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  BufferSize,
    PSIZE_T NumberOfBytesRead);

// static state

static pfnNtOpenProcess             _NtOpenProc;
static pfnNtClose                   _NtClose;
static pfnNtDuplicateObject         _NtDupObj;
static pfnNtQueryInformationProcess _NtQIP;
static pfnNtReadVirtualMemory       _NtRVM;
static BOOL                         _ready;

// init

static MDK_RESULT _init(void) {
    if (_ready) { return MDK_MAKE_OK(); }
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtOpenProcess_H,             (PVOID*)&_NtOpenProc));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtClose_H,                   (PVOID*)&_NtClose));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtDuplicateObject_H,         (PVOID*)&_NtDupObj));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtQueryInformationProcess_H, (PVOID*)&_NtQIP));
    MDK_CHECK(mdk_dfr_resolve(NTDLL_H, NtReadVirtualMemory_H,       (PVOID*)&_NtRVM));
    _ready = TRUE;
    return MDK_MAKE_OK();
}

// handle management

MDK_RESULT mdk_open_process(IN DWORD pid, IN DWORD access, OUT HANDLE* process) {
    MDK_CHECK(_init());
    MDK_OBJ_ATTRS object_attributes = { .Length = sizeof(MDK_OBJ_ATTRS) };
    MDK_CLIENT_ID client_id         = { (HANDLE)(ULONG_PTR)pid, NULL };

    NTSTATUS status = _NtOpenProc(process, access, &object_attributes, &client_id);
    return status ? MDK_MAKE_FAIL("NtOpenProcess", status) : MDK_MAKE_OK();
}

MDK_RESULT mdk_close_handle(IN HANDLE handle) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtClose(handle);
    return status ? MDK_MAKE_FAIL("NtClose", status) : MDK_MAKE_OK();
}

MDK_RESULT mdk_dup_handle(IN HANDLE src_proc, IN HANDLE src, IN HANDLE dst_proc, OUT HANDLE* dst, IN DWORD access) {
    MDK_CHECK(_init());
    NTSTATUS status = _NtDupObj(src_proc, src, dst_proc, dst, access, 0, 0);
    return status ? MDK_MAKE_FAIL("NtDuplicateObject", status) : MDK_MAKE_OK();
}

// process inspection

MDK_RESULT mdk_read_peb(IN HANDLE process, OUT MDK_PEB* peb) {
    PVOID peb_address = NULL;
    MDK_CHECK(mdk_get_peb_address(process, &peb_address));
    return mdk_read(process, peb_address, peb, sizeof(MDK_PEB));
}

MDK_RESULT mdk_get_peb_address(IN HANDLE process, OUT PVOID* address) {
    MDK_CHECK(_init());
    MDK_PROC_BASIC_INFO process_basic_info = { 0 };
    ULONG               return_length      = 0;

    NTSTATUS status = _NtQIP(process, 0, &process_basic_info, sizeof(process_basic_info), &return_length);
    if (status) { return MDK_MAKE_FAIL("NtQueryInformationProcess", status); }

    *address = process_basic_info.PebBaseAddress;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_get_base_address(IN HANDLE process, OUT PVOID* address) {
    MDK_PEB peb = { 0 };
    MDK_CHECK(mdk_read_peb(process, &peb));
    *address = peb.ImageBaseAddress;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_is_wow64(IN HANDLE process, OUT BOOL* result) {
    MDK_CHECK(_init());
    ULONG_PTR wow64_pointer = 0;
    ULONG     return_length = 0;

    NTSTATUS status = _NtQIP(process, 26, &wow64_pointer, sizeof(ULONG_PTR), &return_length);
    if (status) { return MDK_MAKE_FAIL("NtQueryInformationProcess", status); }

    *result = (wow64_pointer != 0);
    return MDK_MAKE_OK();
}

// remote export resolution

MDK_RESULT mdk_resolve_export(IN HANDLE process, IN PVOID remote_base, IN const char* func_name, OUT PVOID* address) {
    MDK_CHECK(_init());
    SIZE_T bytes_read = 0;

    IMAGE_DOS_HEADER dos_header = { 0 };
    NTSTATUS status = _NtRVM(process, remote_base, &dos_header, sizeof(dos_header), &bytes_read);
    if (status || dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        return MDK_MAKE_FAIL("mdk_resolve_export:dos", status ? status : MDK_STATUS_INVALID_IMAGE_FORMAT);
    }

    IMAGE_NT_HEADERS64 nt_headers = { 0 };
    status = _NtRVM(process, (BYTE*)remote_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers), &bytes_read);
    if (status || nt_headers.Signature != IMAGE_NT_SIGNATURE) {
        return MDK_MAKE_FAIL("mdk_resolve_export:nt", status ? status : MDK_STATUS_INVALID_IMAGE_FORMAT);
    }

    IMAGE_DATA_DIRECTORY* export_data_dir = &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!export_data_dir->VirtualAddress || !export_data_dir->Size) {
        return MDK_MAKE_FAIL("mdk_resolve_export:no_exports", MDK_STATUS_NOT_FOUND);
    }

    DWORD export_rva  = export_data_dir->VirtualAddress;
    DWORD export_size = export_data_dir->Size;

    BYTE* export_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, export_size);
    if (!export_buffer) { return MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY); }

    status = _NtRVM(process, (BYTE*)remote_base + export_rva, export_buffer, export_size, &bytes_read);
    if (status) {
        HeapFree(GetProcessHeap(), 0, export_buffer);
        return MDK_MAKE_FAIL("NtReadVirtualMemory", status);
    }

    IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)export_buffer;

    DWORD names_offset     = export_directory->AddressOfNames        - export_rva;
    DWORD ordinals_offset  = export_directory->AddressOfNameOrdinals - export_rva;
    DWORD functions_offset = export_directory->AddressOfFunctions    - export_rva;

    if (names_offset >= export_size || ordinals_offset >= export_size || functions_offset >= export_size) {
        HeapFree(GetProcessHeap(), 0, export_buffer);
        return MDK_MAKE_FAIL("mdk_resolve_export:eat_corrupt", MDK_STATUS_INVALID_IMAGE_FORMAT);
    }

    DWORD* name_table     = (DWORD*)((BYTE*)export_buffer + names_offset);
    WORD*  ordinal_table  = (WORD*) ((BYTE*)export_buffer + ordinals_offset);
    DWORD* function_table = (DWORD*)((BYTE*)export_buffer + functions_offset);

    MDK_RESULT result = MDK_MAKE_FAIL("mdk_resolve_export:not_found", MDK_STATUS_NOT_FOUND);

    for (DWORD i = 0; i < export_directory->NumberOfNames; i++) {
        DWORD name_offset = name_table[i] - export_rva;
        if (name_offset >= export_size) { continue; }

        const char* export_name = (const char*)export_buffer + name_offset;
        DWORD       remaining   = export_size - name_offset;
        DWORD       k;

        for (k = 0; k < remaining; k++) {
            if (export_name[k] == '\0') { break; }
        }
        if (k == remaining) { continue; }

        if (mdk_strcmp(export_name, func_name) == 0) {
            if (ordinal_table[i] >= export_directory->NumberOfFunctions) { continue; }
            *address = (BYTE*)remote_base + function_table[ordinal_table[i]];
            result   = MDK_MAKE_OK();
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, export_buffer);
    return result;
}
