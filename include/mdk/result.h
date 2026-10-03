// MDK
// docs    : https://sebafvs.com/mdk/result
// author  : @sebafvs

#pragma once

#include <windows.h>


typedef struct {
    BOOL        success;
    NTSTATUS    nt_status;
    DWORD       win32_error;
    const char* operation;
    const char* file;
    int         line;
} MDK_RESULT;


#define MDK_OK(result)    ((result).success == TRUE)
#define MDK_FAIL(result)  ((result).success == FALSE)

#define MDK_CHECK(result)                                \
    do {                                                 \
        MDK_RESULT _mdk_result = (result);               \
        if (MDK_FAIL(_mdk_result)) {                     \
            return _mdk_result;                          \
        }                                                \
    } while (0)

#define MDK_MAKE_OK()                                    \
    (MDK_RESULT){                                        \
        .success = TRUE,                                 \
    }

#ifdef MDK_DEBUG
    #define MDK_MAKE_FAIL(_op_arg, _nt_arg)              \
        (MDK_RESULT){                                    \
            .success     = FALSE,                        \
            .operation   = (_op_arg),                    \
            .nt_status   = (_nt_arg),                    \
            .win32_error = GetLastError(),               \
            .file        = __FILE__,                     \
            .line        = __LINE__,                     \
        }
#else
    #define MDK_MAKE_FAIL(_op_arg, _nt_arg)              \
        (MDK_RESULT){                                    \
            .success     = FALSE,                        \
            .operation   = (_op_arg),                    \
            .nt_status   = (_nt_arg),                    \
            .win32_error = GetLastError(),               \
        }
#endif
