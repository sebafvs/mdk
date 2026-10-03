// MDK
// docs    : https://sebafvs.com/mdk/pe
// author  : @sebafvs

#include <windows.h>
#include "mdk/pe.h"
#include "mdk/utils.h"
#include "mdk/nt.h"

// internal helpers

static PIMAGE_DOS_HEADER _dos(PVOID base) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
    return dos_header->e_magic == IMAGE_DOS_SIGNATURE ? dos_header : NULL;
}

static PIMAGE_NT_HEADERS _nt(PVOID base) {
    PIMAGE_DOS_HEADER dos_header = _dos(base);
    if (!dos_header) { return NULL; }
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((PBYTE)base + dos_header->e_lfanew);
    return nt_headers->Signature == IMAGE_NT_SIGNATURE ? nt_headers : NULL;
}

// Name[8] is fixed-width, not null-terminated when exactly 8 chars long.
static int _name_eq(const BYTE raw_name[8], const char* target_name) {
    for (int i = 0; i < 8; i++) {
        if ((BYTE)target_name[i] != raw_name[i]) { return 0; }
        if (target_name[i] == '\0') { return 1; }
    }
    return target_name[8] == '\0';
}

static PVOID _dir(PVOID base, int idx) {
    PIMAGE_NT_HEADERS nt_headers = _nt(base);
    if (!nt_headers) { return NULL; }
    IMAGE_DATA_DIRECTORY data_directory = nt_headers->OptionalHeader.DataDirectory[idx];
    if (!data_directory.VirtualAddress) { return NULL; }
    return (PVOID)((PBYTE)base + data_directory.VirtualAddress);
}

// Forwarded export: RVA falls inside the export directory, pointing to a "DLL.FuncName" string.
static BOOL _forwarded(PVOID base, DWORD rva) {
    PIMAGE_NT_HEADERS nt_headers = _nt(base);
    if (!nt_headers) { return FALSE; }
    IMAGE_DATA_DIRECTORY data_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    return rva >= data_directory.VirtualAddress && rva < data_directory.VirtualAddress + data_directory.Size;
}

// header accessors

PIMAGE_NT_HEADERS mdk_pe_nt(IN PVOID base) {
    return _nt(base);
}

PVOID mdk_pe_rva_to_va(IN PVOID base, IN DWORD rva) {
    return rva ? (PVOID)((PBYTE)base + rva) : NULL;
}

// sections

PIMAGE_SECTION_HEADER mdk_pe_sections(IN PVOID base, OUT WORD* count) {
    PIMAGE_NT_HEADERS nt_headers = _nt(base);
    if (!nt_headers) { return NULL; }
    if (count) { *count = nt_headers->FileHeader.NumberOfSections; }
    return (PIMAGE_SECTION_HEADER)((PBYTE)nt_headers + sizeof(IMAGE_NT_HEADERS));
}

PIMAGE_SECTION_HEADER mdk_pe_section_by_name(IN PVOID base, IN const char* name) {
    WORD                  section_count = 0;
    PIMAGE_SECTION_HEADER sections      = mdk_pe_sections(base, &section_count);
    if (!sections) { return NULL; }

    for (WORD i = 0; i < section_count; i++) {
        if (_name_eq(sections[i].Name, name)) { return &sections[i]; }
    }

    return NULL;
}

PIMAGE_SECTION_HEADER mdk_pe_section_by_rva(IN PVOID base, IN DWORD rva) {
    WORD                  section_count = 0;
    PIMAGE_SECTION_HEADER sections      = mdk_pe_sections(base, &section_count);
    if (!sections) { return NULL; }

    for (WORD i = 0; i < section_count; i++) {
        DWORD section_end = sections[i].VirtualAddress +
                            (sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize
                                                          : sections[i].SizeOfRawData);
        if (rva >= sections[i].VirtualAddress && rva < section_end) { return &sections[i]; }
    }

    return NULL;
}

// data directories

PIMAGE_EXPORT_DIRECTORY mdk_pe_export_dir(IN PVOID base) {
    return (PIMAGE_EXPORT_DIRECTORY)_dir(base, IMAGE_DIRECTORY_ENTRY_EXPORT);
}

PIMAGE_IMPORT_DESCRIPTOR mdk_pe_import_dir(IN PVOID base) {
    return (PIMAGE_IMPORT_DESCRIPTOR)_dir(base, IMAGE_DIRECTORY_ENTRY_IMPORT);
}

PIMAGE_BASE_RELOCATION mdk_pe_reloc_dir(IN PVOID base) {
    return (PIMAGE_BASE_RELOCATION)_dir(base, IMAGE_DIRECTORY_ENTRY_BASERELOC);
}

PIMAGE_TLS_DIRECTORY mdk_pe_tls_dir(IN PVOID base) {
    return (PIMAGE_TLS_DIRECTORY)_dir(base, IMAGE_DIRECTORY_ENTRY_TLS);
}

// export resolution

PVOID mdk_pe_export_by_name(IN PVOID base, IN const char* name) {
    PIMAGE_EXPORT_DIRECTORY export_dir = mdk_pe_export_dir(base);
    if (!export_dir) { return NULL; }

    PDWORD function_names     = (PDWORD)((PBYTE)base + export_dir->AddressOfNames);
    PDWORD function_addresses = (PDWORD)((PBYTE)base + export_dir->AddressOfFunctions);
    PWORD  function_ordinals  = (PWORD) ((PBYTE)base + export_dir->AddressOfNameOrdinals);
    int    name_length        = mdk_strlen(name);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        const char* export_name = (const char*)((PBYTE)base + function_names[i]);

        if (mdk_strlen(export_name) == name_length && mdk_memcmp(export_name, name, name_length) == 0) {
            DWORD rva = function_addresses[function_ordinals[i]];
            if (_forwarded(base, rva)) { return NULL; }
            return (PVOID)((PBYTE)base + rva);
        }
    }

    return NULL;
}

PVOID mdk_pe_export_by_hash(IN PVOID base, IN DWORD hash) {
    PIMAGE_EXPORT_DIRECTORY export_dir = mdk_pe_export_dir(base);
    if (!export_dir) { return NULL; }

    PDWORD function_names     = (PDWORD)((PBYTE)base + export_dir->AddressOfNames);
    PDWORD function_addresses = (PDWORD)((PBYTE)base + export_dir->AddressOfFunctions);
    PWORD  function_ordinals  = (PWORD) ((PBYTE)base + export_dir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        const char* export_name = (const char*)((PBYTE)base + function_names[i]);

        if (mdk_hash(export_name) == hash) {
            DWORD rva = function_addresses[function_ordinals[i]];
            if (_forwarded(base, rva)) { return NULL; }
            return (PVOID)((PBYTE)base + rva);
        }
    }

    return NULL;
}

PVOID mdk_pe_export_by_ordinal(IN PVOID base, IN WORD ordinal) {
    PIMAGE_EXPORT_DIRECTORY export_dir = mdk_pe_export_dir(base);
    if (!export_dir) { return NULL; }
    if (ordinal < (WORD)export_dir->Base) { return NULL; }

    WORD   function_index     = ordinal - (WORD)export_dir->Base;
    if (function_index >= (WORD)export_dir->NumberOfFunctions) { return NULL; }

    PDWORD function_addresses = (PDWORD)((PBYTE)base + export_dir->AddressOfFunctions);
    DWORD  rva                = function_addresses[function_index];

    if (!rva || _forwarded(base, rva)) { return NULL; }
    return (PVOID)((PBYTE)base + rva);
}

// remote PE

MDK_RESULT mdk_pe_read_remote_nt(IN HANDLE process, IN PVOID remote_base, OUT IMAGE_NT_HEADERS* nt) {
    IMAGE_DOS_HEADER dos_header = { 0 };
    SIZE_T           bytes_read = 0;

    if (!ReadProcessMemory(process, remote_base, &dos_header, sizeof(dos_header), &bytes_read) || bytes_read != sizeof(dos_header)) {
        return MDK_MAKE_FAIL("mdk_pe_read_remote_nt:dos_rpm", MDK_STATUS_UNSUCCESSFUL);
    }
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        return MDK_MAKE_FAIL("mdk_pe_read_remote_nt:dos_magic", MDK_STATUS_INVALID_IMAGE_FORMAT);
    }

    PVOID nt_ptr = (PBYTE)remote_base + dos_header.e_lfanew;
    if (!ReadProcessMemory(process, nt_ptr, nt, sizeof(*nt), &bytes_read) || bytes_read != sizeof(*nt)) {
        return MDK_MAKE_FAIL("mdk_pe_read_remote_nt:nt_rpm", MDK_STATUS_UNSUCCESSFUL);
    }
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return MDK_MAKE_FAIL("mdk_pe_read_remote_nt:nt_sig", MDK_STATUS_INVALID_IMAGE_FORMAT);
    }

    return MDK_MAKE_OK();
}
