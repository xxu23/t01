#ifndef T01_CRC32_H
#define T01_CRC32_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif


uint32_t crc32(uint32_t crc, const char *data, size_t n);


#ifdef __cplusplus
}
#endif

#endif //T01_CRC32_H
