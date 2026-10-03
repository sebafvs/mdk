// MDK
// docs    : https://sebafvs.com/mdk/dbg
// author  : @sebafvs

#pragma once

#ifdef MDK_DEBUG

#include <stdio.h>

#define DBG_OK(fmt, ...)     do { printf("[+] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#define DBG_ERR(fmt, ...)    do { printf("[-] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#define DBG_WARN(fmt, ...)   do { printf("[!] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#define DBG_INFO(fmt, ...)   do { printf("[i] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#define DBG_DETAIL(fmt, ...) do { printf("[*] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)
#define DBG_STAGE(n, msg)    do { printf("\n=== [STAGE %d] %s ===\n", (n), (msg)); fflush(stdout); } while (0)

#else

#define DBG_OK(fmt, ...)     ((void)0)
#define DBG_ERR(fmt, ...)    ((void)0)
#define DBG_WARN(fmt, ...)   ((void)0)
#define DBG_INFO(fmt, ...)   ((void)0)
#define DBG_DETAIL(fmt, ...) ((void)0)
#define DBG_STAGE(n, msg)    ((void)0)

#endif
