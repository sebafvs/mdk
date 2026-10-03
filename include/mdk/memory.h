// MDK
// docs    : https://sebafvs.com/mdk/memory
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"


// --- Allocation ---

MDK_RESULT mdk_alloc (IN HANDLE process, IN SIZE_T size, IN DWORD prot, OUT PVOID* address);
MDK_RESULT mdk_free  (IN HANDLE process, IN PVOID base);


// --- Read / Write ---

MDK_RESULT mdk_write (IN HANDLE process, IN PVOID dest, IN const void* src, IN SIZE_T size);
MDK_RESULT mdk_read  (IN HANDLE process, IN PVOID src, OUT void* dest, IN SIZE_T size);


// --- Protection ---

MDK_RESULT mdk_protect (IN HANDLE process, IN PVOID addr, IN SIZE_T size, IN DWORD new_prot, OUT DWORD* old_prot);
MDK_RESULT mdk_query   (IN HANDLE process, IN PVOID addr, OUT MEMORY_BASIC_INFORMATION* mbi);


// --- Composed ---

MDK_RESULT mdk_write_exec (IN HANDLE process, IN PVOID addr, IN const void* data, IN SIZE_T size);


// --- Section-based ---

MDK_RESULT mdk_create_section       (IN SIZE_T size, IN DWORD protect, OUT HANDLE* section);
MDK_RESULT mdk_create_section_image (IN HANDLE file_handle, OUT HANDLE* section);
MDK_RESULT mdk_map                  (IN HANDLE section, IN HANDLE process, IN SIZE_T size, IN DWORD protect, OUT PVOID* address);
MDK_RESULT mdk_unmap                (IN HANDLE process, IN PVOID base);


// --- Utils ---

MDK_RESULT mdk_entropy_pad (IN const BYTE* payload, IN SIZE_T size, IN BYTE pad_byte, IN SIZE_T pad_count, OUT BYTE** out, OUT SIZE_T* out_size);
