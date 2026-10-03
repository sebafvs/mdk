// MDK
// docs    : https://sebafvs.com/mdk/staging
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"


MDK_RESULT mdk_fetch_payload     (IN LPCWSTR url, OUT PBYTE* payload, OUT SIZE_T* size);
MDK_RESULT mdk_reg_write_payload (IN HKEY root, IN LPCSTR key_path, IN LPCSTR value_name, IN const BYTE* payload, IN SIZE_T size);
MDK_RESULT mdk_reg_read_payload  (IN HKEY root, IN LPCSTR key_path, IN LPCSTR value_name, OUT PBYTE* payload, OUT SIZE_T* size);
