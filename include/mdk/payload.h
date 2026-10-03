// MDK
// docs    : https://sebafvs.com/mdk/payload
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "result.h"


MDK_RESULT mdk_read_file (IN const char* path, OUT PBYTE* data, OUT SIZE_T* size);
