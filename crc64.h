#ifndef CRC64_H
#define CRC64_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t crc64(uint64_t crc, const unsigned char *s, uint64_t l);

uint64_t crc64_2(uint64_t crc, uint8_t value);

#ifdef __cplusplus
}
#endif

#endif