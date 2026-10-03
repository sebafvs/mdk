// MDK
// docs    : https://sebafvs.com/mdk/encode
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"


// --- XOR ---

void mdk_xor (IN const BYTE* key, IN SIZE_T key_size, IN OUT BYTE* payload, IN SIZE_T payload_size);


// --- RC4 ---

MDK_RESULT mdk_rc4_brute   (IN const BYTE* protected_key, IN SIZE_T key_size, IN BYTE hint_byte, OUT BYTE* real_key);
MDK_RESULT mdk_rc4_decrypt (IN const BYTE* key, IN SIZE_T key_size, IN OUT BYTE* payload, IN SIZE_T payload_size);


// --- AES-256-CBC ---

MDK_RESULT mdk_aes_decrypt (IN const BYTE* key, IN SIZE_T key_size, IN const BYTE* iv, IN OUT BYTE* payload, IN SIZE_T payload_size);


// --- Deobfuscation ---

MDK_RESULT mdk_ipv4_deobfuscate (IN const char** ipv4_array, IN SIZE_T count, OUT BYTE* payload);
MDK_RESULT mdk_ipv6_deobfuscate (IN const char** ipv6_array, IN SIZE_T count, OUT BYTE* payload);
MDK_RESULT mdk_mac_deobfuscate  (IN const char** mac_array, IN SIZE_T count, OUT BYTE* payload);
MDK_RESULT mdk_uuid_deobfuscate (IN const char** uuid_array, IN SIZE_T count, OUT BYTE* payload);
