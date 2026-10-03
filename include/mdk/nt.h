// MDK
// docs    : https://sebafvs.com/mdk/nt
// author  : @sebafvs

#pragma once

#include <windows.h>


// https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MDK_USTR;

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    MDK_USTR   FullDllName;
    MDK_USTR   BaseDllName;
} MDK_LDR_ENTRY;

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
typedef struct {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MDK_LDR_DATA;

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters
// Only exposes the fields needed for argument spoofing; the real struct is much larger.
typedef struct {
    BYTE     Reserved1[16];
    PVOID    Reserved2[10];
    MDK_USTR ImagePathName;
    MDK_USTR CommandLine;
} MDK_RTL_PROC_PARAMS;

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb
typedef struct {
    BOOLEAN                InheritedAddressSpace;
    BOOLEAN                ReadImageFileExecOptions;
    BOOLEAN                BeingDebugged;
    BOOLEAN                SpareBool;
    HANDLE                 Mutant;
    PVOID                  ImageBaseAddress;
    MDK_LDR_DATA*          Ldr;
    MDK_RTL_PROC_PARAMS*   ProcessParameters;  // offset 0x20 on x64
} MDK_PEB;

// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
typedef struct {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} MDK_OBJ_ATTRS;

// https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MDK_CLIENT_ID;

// https://github.com/winsiderss/phnt/blob/master/ntexapi.h
// SYSTEM_THREAD_INFORMATION entries follow immediately at (entry + sizeof(MDK_SYS_PROC)).
typedef struct {
    ULONG         NextEntryOffset;
    ULONG         NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG         HardFaultCount;
    ULONG         NumberOfThreadsHighWatermark;
    ULONGLONG     CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    MDK_USTR      ImageName;
    LONG          BasePriority;
    HANDLE        UniqueProcessId;
    HANDLE        InheritedFromUniqueProcessId;
    ULONG         HandleCount;
    ULONG         SessionId;
    ULONG_PTR     PageDirectoryBase;
    SIZE_T        PeakVirtualSize;
    SIZE_T        VirtualSize;
    ULONG         PageFaultCount;
    SIZE_T        PeakWorkingSetSize;
    SIZE_T        WorkingSetSize;
    SIZE_T        QuotaPeakPagedPoolUsage;
    SIZE_T        QuotaPagedPoolUsage;
    SIZE_T        QuotaPeakNonPagedPoolUsage;
    SIZE_T        QuotaNonPagedPoolUsage;
    SIZE_T        PagefileUsage;
    SIZE_T        PeakPagefileUsage;
    SIZE_T        PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} MDK_SYS_PROC;

// NTSTATUS constants, avoids pulling in ntstatus.h (WDK header with include-order conflicts)
#define MDK_STATUS_UNSUCCESSFUL           0xC0000001
#define MDK_STATUS_NOT_IMPLEMENTED        0xC0000002
#define MDK_STATUS_ACCESS_VIOLATION       0xC0000005
#define MDK_STATUS_INVALID_PARAMETER      0xC000000D
#define MDK_STATUS_NO_MEMORY              0xC0000017
#define MDK_STATUS_ACCESS_DENIED          0xC0000022
#define MDK_STATUS_OBJECT_NAME_NOT_FOUND  0xC0000034
#define MDK_STATUS_INVALID_IMAGE_FORMAT   0xC000007B
#define MDK_STATUS_INSUFFICIENT_RESOURCES 0xC000009A
#define MDK_STATUS_DLL_NOT_FOUND          0xC0000135
#define MDK_STATUS_ENTRYPOINT_NOT_FOUND   0xC0000139
#define MDK_STATUS_NOT_FOUND              0xC0000225

static inline const char* mdk_status_str(NTSTATUS s) {
    switch (s) {
    case MDK_STATUS_UNSUCCESSFUL:           return "STATUS_UNSUCCESSFUL";
    case MDK_STATUS_NOT_IMPLEMENTED:        return "STATUS_NOT_IMPLEMENTED";
    case MDK_STATUS_ACCESS_VIOLATION:       return "STATUS_ACCESS_VIOLATION";
    case MDK_STATUS_INVALID_PARAMETER:      return "STATUS_INVALID_PARAMETER";
    case MDK_STATUS_NO_MEMORY:              return "STATUS_NO_MEMORY";
    case MDK_STATUS_ACCESS_DENIED:          return "STATUS_ACCESS_DENIED";
    case MDK_STATUS_OBJECT_NAME_NOT_FOUND:  return "STATUS_OBJECT_NAME_NOT_FOUND";
    case MDK_STATUS_INVALID_IMAGE_FORMAT:   return "STATUS_INVALID_IMAGE_FORMAT";
    case MDK_STATUS_INSUFFICIENT_RESOURCES: return "STATUS_INSUFFICIENT_RESOURCES";
    case MDK_STATUS_DLL_NOT_FOUND:          return "STATUS_DLL_NOT_FOUND";
    case MDK_STATUS_ENTRYPOINT_NOT_FOUND:   return "STATUS_ENTRYPOINT_NOT_FOUND";
    case MDK_STATUS_NOT_FOUND:              return "STATUS_NOT_FOUND";
    default:                                return NULL;
    }
}

static inline MDK_PEB* mdk_get_peb(void) {
#ifdef _WIN64
    return (MDK_PEB*)__readgsqword(0x60);
#else
    return (MDK_PEB*)__readfsdword(0x30);
#endif
}
