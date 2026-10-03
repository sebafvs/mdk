// MDK
// docs    : https://sebafvs.com/mdk/payload
// author  : @sebafvs

#include <windows.h>
#include "mdk/payload.h"
#include "mdk/nt.h"

MDK_RESULT mdk_read_file(IN const char* path, OUT PBYTE* data, OUT SIZE_T* size) {
    HANDLE file_handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) { return MDK_MAKE_FAIL("CreateFileA", MDK_STATUS_NOT_FOUND); }

    LARGE_INTEGER file_size = { 0 };
    if (!GetFileSizeEx(file_handle, &file_size)) {
        CloseHandle(file_handle);
        return MDK_MAKE_FAIL("GetFileSizeEx", MDK_STATUS_UNSUCCESSFUL);
    }
    if (file_size.QuadPart == 0 || file_size.QuadPart > 0x10000000) {
        CloseHandle(file_handle);
        return MDK_MAKE_FAIL("mdk_read_file:size", MDK_STATUS_INVALID_PARAMETER);
    }

    SIZE_T buffer_size = (SIZE_T)file_size.QuadPart;
    PBYTE  buffer      = (PBYTE)HeapAlloc(GetProcessHeap(), 0, buffer_size);
    if (!buffer) {
        CloseHandle(file_handle);
        return MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY);
    }

    SIZE_T total_read = 0;
    while (total_read < buffer_size) {
        DWORD chunk       = (DWORD)((buffer_size - total_read) > 0x100000 ? 0x100000 : (buffer_size - total_read));
        DWORD bytes_read  = 0;
        if (!ReadFile(file_handle, buffer + total_read, chunk, &bytes_read, NULL) || bytes_read == 0) {
            HeapFree(GetProcessHeap(), 0, buffer);
            CloseHandle(file_handle);
            return MDK_MAKE_FAIL("ReadFile", MDK_STATUS_UNSUCCESSFUL);
        }
        total_read += bytes_read;
    }

    CloseHandle(file_handle);
    *data = buffer;
    *size = buffer_size;
    return MDK_MAKE_OK();
}

