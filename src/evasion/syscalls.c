// MDK
// docs    : https://sebafvs.com/mdk/syscalls
// author  : @sebafvs

#include <windows.h>
#include "mdk/syscalls.h"
#include "mdk/utils.h"
#include "mdk/nt.h"
#include "mdk/hashes.h"

// syscall table

#define SC_MAX 500

typedef struct {
    DWORD zw_hash;
    DWORD ssn;
    PVOID address;
    PVOID gadget;
} _SC_ENTRY;

static _SC_ENTRY _sc_list[SC_MAX];
static DWORD     _sc_count;
static BOOL      _sc_ready;

// internal helpers

// Finds ntdll base via PEB walk. Uses |0x20 for case-insensitive char comparison.
static PVOID _get_ntdll(void) {
    MDK_PEB*      peb  = mdk_get_peb();
    MDK_LDR_DATA* ldr  = peb->Ldr;
    PLIST_ENTRY   head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY   node = head->Flink;

    while (node != head) {
        MDK_LDR_ENTRY* ldr_entry = CONTAINING_RECORD(node, MDK_LDR_ENTRY, InLoadOrderLinks);

        if (ldr_entry->BaseDllName.Buffer && ldr_entry->BaseDllName.Length >= 12) {
            WCHAR* module_name = ldr_entry->BaseDllName.Buffer;

            if ((module_name[0] | 0x20) == L'n' &&
                (module_name[1] | 0x20) == L't' &&
                (module_name[2] | 0x20) == L'd' &&
                (module_name[3] | 0x20) == L'l' &&
                (module_name[4] | 0x20) == L'l' &&
                 module_name[5]         == L'.') {
                return ldr_entry->DllBase;
            }
        }

        node = node->Flink;
    }

    return NULL;
}

static PVOID _find_gadget(PVOID func_va) {
    static const BYTE sig[3] = { 0x0F, 0x05, 0xC3 }; // syscall; ret
    PBYTE function_bytes = (PBYTE)func_va;

    if (mdk_memcmp(function_bytes + 0x12, sig, 3) == 0) { return function_bytes + 0x12; }
    if (mdk_memcmp(function_bytes + 0x11, sig, 3) == 0) { return function_bytes + 0x11; }

    for (int stub_offset = 1; stub_offset <= 64; stub_offset++) {
        if (mdk_memcmp(function_bytes + 0x12 + stub_offset * 0x20, sig, 3) == 0) {
            return function_bytes + 0x12 + stub_offset * 0x20;
        }

        if ((SIZE_T)(function_bytes + 0x12) > (SIZE_T)(stub_offset * 0x20) &&
             mdk_memcmp(function_bytes + 0x12 - stub_offset * 0x20, sig, 3) == 0) {
            return function_bytes + 0x12 - stub_offset * 0x20;
        }
    }

    return NULL;
}

// Insertion sort by VA; sorted position becomes the SSN (SW2 method).
static void _sort(void) {
    for (DWORD i = 1; i < _sc_count; i++) {
        _SC_ENTRY current_entry  = _sc_list[i];
        DWORD     insert_position = i;

        while (insert_position > 0 && (ULONG_PTR)_sc_list[insert_position - 1].address > (ULONG_PTR)current_entry.address) {
            _sc_list[insert_position] = _sc_list[insert_position - 1];
            insert_position--;
        }

        _sc_list[insert_position] = current_entry;
    }
}

// Walks the ntdll EAT, collects all Zw* exports, finds gadgets, then sorts to assign SSNs.
static BOOL _populate(PVOID ntdll) {
    PBYTE             base       = (PBYTE)ntdll;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;

    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) { return FALSE; }

    PIMAGE_NT_HEADERS    nt_headers      = (PIMAGE_NT_HEADERS)(base + dos_header->e_lfanew);
    IMAGE_DATA_DIRECTORY export_data_dir = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!export_data_dir.VirtualAddress) { return FALSE; }

    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(base + export_data_dir.VirtualAddress);
    PDWORD function_names     = (PDWORD)(base + export_dir->AddressOfNames);
    PDWORD function_addresses = (PDWORD)(base + export_dir->AddressOfFunctions);
    PWORD  function_ordinals  = (PWORD) (base + export_dir->AddressOfNameOrdinals);
    _sc_count = 0;

    for (DWORD i = 0; i < export_dir->NumberOfNames && _sc_count < SC_MAX; i++) {
        LPCSTR function_name = (LPCSTR)(base + function_names[i]);

        if (function_name[0] != 'Z' || function_name[1] != 'w') { continue; }

        DWORD rva = function_addresses[function_ordinals[i]];
        if (rva >= export_data_dir.VirtualAddress && rva < export_data_dir.VirtualAddress + export_data_dir.Size) {
            continue; // forwarded export
        }

        PVOID function_address = base + rva;
        _sc_list[_sc_count].zw_hash = mdk_hash(function_name);
        _sc_list[_sc_count].address = function_address;

        PVOID gadget = _find_gadget(function_address);
        _sc_list[_sc_count].gadget  = gadget ? gadget : (PBYTE)function_address + 0x12;
        _sc_list[_sc_count].ssn     = 0;
        _sc_count++;
    }

    if (!_sc_count) { return FALSE; }

    _sort();

    for (DWORD i = 0; i < _sc_count; i++) { _sc_list[i].ssn = i; }
    return TRUE;
}

// public API, called at runtime from the naked stubs via inline asm

MDK_RESULT mdk_sc_init(void) {
    if (_sc_ready) { return MDK_MAKE_OK(); }

    PVOID ntdll = _get_ntdll();
    if (!ntdll) { return MDK_MAKE_FAIL("mdk_sc_init:ntdll", MDK_STATUS_DLL_NOT_FOUND); }

    if (!_populate(ntdll)) { return MDK_MAKE_FAIL("mdk_sc_init:populate", MDK_STATUS_ACCESS_DENIED); }

    _sc_ready = TRUE;
    return MDK_MAKE_OK();
}

static const _SC_ENTRY* _find(DWORD zw_hash) {
    for (DWORD i = 0; i < _sc_count; i++) {
        if (_sc_list[i].zw_hash == zw_hash) { return &_sc_list[i]; }
    }
    return NULL;
}

DWORD mdk_sc_get_ssn(IN DWORD zw_hash) {
    if (MDK_FAIL(mdk_sc_init())) { return 0xFFFFFFFF; }
    const _SC_ENTRY* entry = _find(zw_hash);
    return entry ? entry->ssn : 0xFFFFFFFF;
}

PVOID mdk_sc_get_gadget(IN DWORD zw_hash) {
    if (MDK_FAIL(mdk_sc_init())) { return NULL; }
    const _SC_ENTRY* entry = _find(zw_hash);
    return entry ? entry->gadget : NULL;
}

MDK_RESULT mdk_sc_free(void) {
    _sc_ready = FALSE;
    _sc_count = 0;
    return MDK_MAKE_OK();
}

// SW3-style indirect syscall stubs. Full walkthrough: https://sebafvs.com/mdk/syscalls

// Double-expansion stringify: _SC_XST(ZwSuspendThread_H) -> "0x57DC505F"
#define _SC_STR(x) #x
#define _SC_XST(x) _SC_STR(x)

#define _STUB(name, hash)                       \
__attribute__((naked, noinline))                \
static NTSTATUS NTAPI _stub_##name(void) {      \
    __asm__ (                                   \
        ".intel_syntax noprefix\n\t"            \
        "mov [rsp+8],  rcx\n\t"                 \
        "mov [rsp+16], rdx\n\t"                 \
        "mov [rsp+24], r8\n\t"                  \
        "mov [rsp+32], r9\n\t"                  \
        "sub rsp, 40\n\t"                       \
        "mov ecx, " _SC_XST(hash) "\n\t"        \
        "call mdk_sc_get_gadget\n\t"            \
        "mov r15, rax\n\t"                      \
        "mov ecx, " _SC_XST(hash) "\n\t"        \
        "call mdk_sc_get_ssn\n\t"               \
        "add rsp, 40\n\t"                       \
        "mov rcx, [rsp+8]\n\t"                  \
        "mov rdx, [rsp+16]\n\t"                 \
        "mov r8,  [rsp+24]\n\t"                 \
        "mov r9,  [rsp+32]\n\t"                 \
        "mov r10, rcx\n\t"                      \
        "jmp r15\n\t"                           \
        ".att_syntax prefix\n\t"                \
    );                                          \
}

// Thread
_STUB(ZwSuspendThread,           ZwSuspendThread_H)
_STUB(ZwResumeThread,            ZwResumeThread_H)
_STUB(ZwGetContextThread,        ZwGetContextThread_H)
_STUB(ZwSetContextThread,        ZwSetContextThread_H)
_STUB(ZwOpenThread,              ZwOpenThread_H)
_STUB(ZwClose,                   ZwClose_H)
_STUB(ZwCreateThreadEx,          ZwCreateThreadEx_H)

// Memory
_STUB(ZwAllocateVirtualMemory,   ZwAllocateVirtualMemory_H)
_STUB(ZwFreeVirtualMemory,       ZwFreeVirtualMemory_H)
_STUB(ZwProtectVirtualMemory,    ZwProtectVirtualMemory_H)
_STUB(ZwReadVirtualMemory,       ZwReadVirtualMemory_H)
_STUB(ZwWriteVirtualMemory,      ZwWriteVirtualMemory_H)
_STUB(ZwQueryVirtualMemory,      ZwQueryVirtualMemory_H)

// Process
_STUB(ZwOpenProcess,             ZwOpenProcess_H)
_STUB(ZwTerminateProcess,        ZwTerminateProcess_H)

// Section
_STUB(ZwCreateSection,           ZwCreateSection_H)
_STUB(ZwMapViewOfSection,        ZwMapViewOfSection_H)
_STUB(ZwUnmapViewOfSection,      ZwUnmapViewOfSection_H)

// Other
_STUB(ZwQuerySystemInformation,  ZwQuerySystemInformation_H)
_STUB(ZwWaitForSingleObject,     ZwWaitForSingleObject_H)

#undef _STUB

// dispatch table, hash -> .text stub pointer

typedef struct { DWORD zw_hash; PVOID stub; } _SC_DISPATCH;

static const _SC_DISPATCH _dispatch[] = {
    { ZwSuspendThread_H,          (PVOID)_stub_ZwSuspendThread          },
    { ZwResumeThread_H,           (PVOID)_stub_ZwResumeThread           },
    { ZwGetContextThread_H,       (PVOID)_stub_ZwGetContextThread       },
    { ZwSetContextThread_H,       (PVOID)_stub_ZwSetContextThread       },
    { ZwOpenThread_H,             (PVOID)_stub_ZwOpenThread             },
    { ZwClose_H,                  (PVOID)_stub_ZwClose                  },
    { ZwCreateThreadEx_H,         (PVOID)_stub_ZwCreateThreadEx         },
    { ZwAllocateVirtualMemory_H,  (PVOID)_stub_ZwAllocateVirtualMemory  },
    { ZwFreeVirtualMemory_H,      (PVOID)_stub_ZwFreeVirtualMemory      },
    { ZwProtectVirtualMemory_H,   (PVOID)_stub_ZwProtectVirtualMemory   },
    { ZwReadVirtualMemory_H,      (PVOID)_stub_ZwReadVirtualMemory      },
    { ZwWriteVirtualMemory_H,     (PVOID)_stub_ZwWriteVirtualMemory     },
    { ZwQueryVirtualMemory_H,     (PVOID)_stub_ZwQueryVirtualMemory     },
    { ZwOpenProcess_H,            (PVOID)_stub_ZwOpenProcess            },
    { ZwTerminateProcess_H,       (PVOID)_stub_ZwTerminateProcess       },
    { ZwCreateSection_H,          (PVOID)_stub_ZwCreateSection          },
    { ZwMapViewOfSection_H,       (PVOID)_stub_ZwMapViewOfSection       },
    { ZwUnmapViewOfSection_H,     (PVOID)_stub_ZwUnmapViewOfSection     },
    { ZwQuerySystemInformation_H, (PVOID)_stub_ZwQuerySystemInformation },
    { ZwWaitForSingleObject_H,    (PVOID)_stub_ZwWaitForSingleObject    },
};

#define _DISPATCH_COUNT (sizeof(_dispatch) / sizeof(_dispatch[0]))

MDK_RESULT mdk_sc_resolve(IN DWORD zw_hash, OUT PVOID* stub) {
    // Callers get an early error rather than a first-call fault inside a stub.
    MDK_CHECK(mdk_sc_init());

    for (DWORD i = 0; i < _DISPATCH_COUNT; i++) {
        if (_dispatch[i].zw_hash == zw_hash) {
            *stub = _dispatch[i].stub;
            return MDK_MAKE_OK();
        }
    }

    return MDK_MAKE_FAIL("mdk_sc_resolve:not_found", MDK_STATUS_OBJECT_NAME_NOT_FOUND);
}
