// MDK
// docs    : https://sebafvs.com/mdk/dfr
// author  : @sebafvs

#include <windows.h>
#include "mdk/evasion.h"
#include "mdk/utils.h"
#include "mdk/nt.h"

// Walk PEB InLoadOrderModuleList, uppercase+hash BaseDllName, return DllBase.
static HMODULE _find_module(DWORD module_hash) {
    MDK_PEB*      peb  = mdk_get_peb();
    MDK_LDR_DATA* ldr  = peb->Ldr;
    PLIST_ENTRY   head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY   node = head->Flink;

    while (node != head) {
        MDK_LDR_ENTRY* entry = CONTAINING_RECORD(node, MDK_LDR_ENTRY, InLoadOrderLinks);

        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length && entry->BaseDllName.Length < 64 * sizeof(WCHAR)) {
            CHAR   uppercase_name[64] = { 0 };
            USHORT name_length        = entry->BaseDllName.Length / sizeof(WCHAR);

            for (USHORT i = 0; i < name_length; i++) {
                WCHAR wide_char       = entry->BaseDllName.Buffer[i];
                uppercase_name[i]     = (CHAR)((wide_char >= L'a' && wide_char <= L'z') ? wide_char - 32 : wide_char);
            }

            if (mdk_hash(uppercase_name) == module_hash) { return (HMODULE)entry->DllBase; }
        }

        node = node->Flink;
    }

    return NULL;
}

static FARPROC _find_export(HMODULE module_handle, DWORD func_hash) {
    PBYTE base = (PBYTE)module_handle;

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) { return NULL; }

    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) { return NULL; }

    IMAGE_DATA_DIRECTORY export_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!export_directory.VirtualAddress) { return NULL; }

    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(base + export_directory.VirtualAddress);

    PDWORD function_names     = (PDWORD)(base + export_dir->AddressOfNames);
    PDWORD function_addresses = (PDWORD)(base + export_dir->AddressOfFunctions);
    PWORD  function_ordinals  = (PWORD) (base + export_dir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        LPCSTR function_name = (LPCSTR)(base + function_names[i]);

        if (mdk_hash(function_name) == func_hash) {
            DWORD rva = function_addresses[function_ordinals[i]];

            if (rva >= export_directory.VirtualAddress && rva < export_directory.VirtualAddress + export_directory.Size) {
                return NULL;
            }

            return (FARPROC)(base + rva);
        }
    }

    return NULL;
}

MDK_RESULT mdk_dfr_resolve(IN DWORD module_hash, IN DWORD func_hash, OUT PVOID* address) {
    HMODULE module_handle = _find_module(module_hash);
    if (!module_handle) { return MDK_MAKE_FAIL("mdk_dfr_resolve:module", MDK_STATUS_DLL_NOT_FOUND); }

    FARPROC function_address = _find_export(module_handle, func_hash);
    if (!function_address) { return MDK_MAKE_FAIL("mdk_dfr_resolve:func", MDK_STATUS_ENTRYPOINT_NOT_FOUND); }

    *address = (PVOID)function_address;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_dfr_resolve_name(IN const char* module, IN const char* func, OUT PVOID* address) {
    CHAR uppercase_module[64] = { 0 };

    for (int i = 0; module[i] && i < 63; i++) {
        CHAR character        = module[i];
        uppercase_module[i]   = (character >= 'a' && character <= 'z') ? character - 32 : character;
    }

    return mdk_dfr_resolve(mdk_hash(uppercase_module), mdk_hash(func), address);
}
