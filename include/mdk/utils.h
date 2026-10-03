// MDK
// docs    : https://sebafvs.com/mdk/utils
// author  : @sebafvs

#pragma once

#include <windows.h>


static inline void* mdk_memcpy(OUT void* dst, IN const void* src, IN size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) *d++ = *s++;
    return dst;
}

static inline void* mdk_memset(OUT void* dst, IN int c, IN size_t n) {
    unsigned char* d = (unsigned char*)dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

static inline int mdk_memcmp(IN const void* a, IN const void* b, IN size_t n) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    while (n--) {
        if (*pa != *pb) return *pa - *pb;
        pa++; pb++;
    }
    return 0;
}

static inline int mdk_strlen(IN const char* s) {
    int n = 0;
    while (*s++) n++;
    return n;
}

static inline int mdk_wcslen(IN const wchar_t* s) {
    int n = 0;
    while (*s++) n++;
    return n;
}

static inline int mdk_strcmp(IN const char* a, IN const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static inline int mdk_wcscmp(IN const wchar_t* a, IN const wchar_t* b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)*a - (int)*b;
}

static inline void mdk_to_lowercase(IN OUT char* s) {
    while (*s) {
        if (*s >= 'A' && *s <= 'Z') *s += 32;
        s++;
    }
}

static inline DWORD mdk_hash(IN const char* s) {
    DWORD h = 0;
    for (SIZE_T i = 0; s[i]; i++) {
        h += (DWORD)(unsigned char)s[i];
        h += h << 10;
        h ^= h >> 6;
    }
    h += h << 3;
    h ^= h >> 11;
    h += h << 15;
    return h;
}

static inline DWORD mdk_rand(void) {
    static DWORD seed = 0x12345678;
    seed = seed * 1664525 + 1013904223;
    return seed;
}
