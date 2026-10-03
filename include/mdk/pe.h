// MDK
// docs    : https://sebafvs.com/mdk/pe
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"


// --- Header accessors ---

PIMAGE_NT_HEADERS mdk_pe_nt        (IN PVOID base);
PVOID             mdk_pe_rva_to_va (IN PVOID base, IN DWORD rva);


// --- Sections ---

PIMAGE_SECTION_HEADER mdk_pe_sections        (IN PVOID base, OUT WORD* count);
PIMAGE_SECTION_HEADER mdk_pe_section_by_name (IN PVOID base, IN const char* name);
PIMAGE_SECTION_HEADER mdk_pe_section_by_rva  (IN PVOID base, IN DWORD rva);


// --- Data directories ---

PIMAGE_EXPORT_DIRECTORY  mdk_pe_export_dir (IN PVOID base);
PIMAGE_IMPORT_DESCRIPTOR mdk_pe_import_dir (IN PVOID base);
PIMAGE_BASE_RELOCATION   mdk_pe_reloc_dir  (IN PVOID base);
PIMAGE_TLS_DIRECTORY     mdk_pe_tls_dir    (IN PVOID base);


// --- Export resolution ---

PVOID mdk_pe_export_by_name    (IN PVOID base, IN const char* name);
PVOID mdk_pe_export_by_hash    (IN PVOID base, IN DWORD hash);
PVOID mdk_pe_export_by_ordinal (IN PVOID base, IN WORD ordinal);


// --- Remote read ---

MDK_RESULT mdk_pe_read_remote_nt (IN HANDLE process, IN PVOID remote_base, OUT IMAGE_NT_HEADERS* nt);
