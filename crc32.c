#include "crc32.h"

#ifdef __x86_64__
#define ALIGN_SIZE 8
#else
#define ALIGN_SIZE 4
#endif
#define ALIGN_MASK (ALIGN_SIZE - 1)

inline uint64_t _mm_crc32_u64(uint64_t crc, uint64_t value) {
    asm("crc32q %[value], %[crc]\n" : [crc] "+r" (crc) : [value] "rm" (value));
    return crc;
}

inline uint32_t _mm_crc32_u32(uint32_t crc, uint32_t value) {
    asm("crc32l %[value], %[crc]\n" : [crc] "+r" (crc) : [value] "rm" (value));
    return crc;
}

inline uint32_t _mm_crc32_u16(uint32_t crc, uint16_t value) {
    asm("crc32w %[value], %[crc]\n" : [crc] "+r" (crc) : [value] "rm" (value));
    return crc;
}

inline uint32_t _mm_crc32_u8(uint32_t crc, uint8_t value) {
    asm("crc32b %[value], %[crc]\n" : [crc] "+r" (crc) : [value] "rm" (value));
    return crc;
}

uint32_t extend(uint32_t init_crc, const char *data, size_t n) {
    uint32_t res = init_crc ^ 0xffffffff;
    size_t i;
#ifdef __x86_64__
    uint64_t *ptr_u64;
    uint64_t tmp;
#endif
    uint32_t *ptr_u32;
    uint16_t *ptr_u16;
    uint8_t *ptr_u8;

    // aligned to machine word's boundary
    for (i = 0; (i < n) && ((intptr_t)(data + i) & ALIGN_MASK); ++i) {
        res = _mm_crc32_u8(res, data[i]);
    }

#ifdef __x86_64__
    tmp = res;
    while (n - i >= sizeof(uint64_t)) {
        ptr_u64 = (uint64_t *)&data[i];
        tmp = _mm_crc32_u64(tmp, *ptr_u64);
        i += sizeof(uint64_t);
    }
    res = (uint32_t)tmp;
#endif
    while (n - i >= sizeof(uint32_t)) {
        ptr_u32 = (uint32_t *)&data[i];
        res = _mm_crc32_u32(res, *ptr_u32);
        i += sizeof(uint32_t);
    }
    while (n - i >= sizeof(uint16_t)) {
        ptr_u16 = (uint16_t *)&data[i];
        res = _mm_crc32_u16(res, *ptr_u16);
        i += sizeof(uint16_t);
    }
    while (n - i >= sizeof(uint8_t)) {
        ptr_u8 = (uint8_t *)&data[i];
        res = _mm_crc32_u8(res, *ptr_u8);
        i += sizeof(uint8_t);
    }

    return res ^ 0xffffffff;
}

uint32_t crc32(uint32_t crc, const char *data, size_t n) {
    return extend(crc, data, n);
}