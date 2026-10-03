// MDK
// docs    : https://sebafvs.com/mdk/hashes
// author  : @sebafvs

#pragma once


// --- Modules ---

#define NTDLL_H     0xD36E54C1
#define KERNEL32_H  0xCC296063
#define USER32_H    0xA2B1A3C7
#define ADVAPI32_H  0x1B4C7C29


// --- DFR targets (used with mdk_dfr_resolve) ---

// ntdll, thread
#define NtSuspendThread_H           0xFCD792CE
#define NtResumeThread_H            0x918A52F1
#define NtGetContextThread_H        0xF864F3BD
#define NtSetContextThread_H        0xAFB6E057
#define NtOpenThread_H              0x079D638A
#define NtClose_H                   0xB1D7C572
#define NtCreateThreadEx_H          0xE5F15DAA
#define NtSuspendProcess_H          0xFAC51EE5
#define NtResumeProcess_H           0xCAF99E30
#define NtQueueApcThread_H          0xCD2A07EC

// ntdll, process
#define NtOpenProcess_H             0x61CF38BC
#define NtDuplicateObject_H         0x86426FE8
#define NtQueryInformationProcess_H 0xE873107E
#define NtOpenProcessToken_H        0xD5D4A26D
#define NtQueryInformationToken_H   0x28CEAE31
#define NtReadVirtualMemory_H       0x026DA588

// ntdll, system info
#define NtQuerySystemInformation_H  0x62A8E2DE
#define RtlGetVersion_H             0xBCB6758E

// kernel32
#define CreateFileW_H               0x9A3D82E5

// user32
#define FindWindowW_H               0x90F646C3
#define GetWindowThreadProcessId_H  0xF703DD15


// --- SW3 indirect syscall targets (used with mdk_sc_resolve, Zw* only) ---

// Thread
#define ZwSuspendThread_H           0x57DC505F
#define ZwResumeThread_H            0xA8719087
#define ZwGetContextThread_H        0x90AD6105
#define ZwSetContextThread_H        0xB1703ECF
#define ZwOpenThread_H              0x6447B896
#define ZwClose_H                   0xEA03AA98
#define ZwCreateThreadEx_H          0x697BAB78

// Memory
#define ZwAllocateVirtualMemory_H   0xAA2CB982
#define ZwFreeVirtualMemory_H       0xEC5F5DFD
#define ZwProtectVirtualMemory_H    0x963BA65C
#define ZwReadVirtualMemory_H       0x373EA9C9
#define ZwWriteVirtualMemory_H      0xA4456CA7
#define ZwQueryVirtualMemory_H      0x3FEF9422

// Process
#define ZwOpenProcess_H             0xAD1E7302
#define ZwTerminateProcess_H        0xFF762762

// Section
#define ZwCreateSection_H           0x7B783455
#define ZwMapViewOfSection_H        0x470A768C
#define ZwUnmapViewOfSection_H      0x6FA5BB18

// System
#define ZwQuerySystemInformation_H  0x6A9D396F
#define ZwWaitForSingleObject_H     0x026045BB
