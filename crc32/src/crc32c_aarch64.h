#ifndef CRC32C_AARCH64_H
#define CRC32C_AARCH64_H

#include "arm.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_ARMV8_CRC

extern uint32_t ceph_crc32c_aarch64(uint32_t crc, unsigned char const *buffer, unsigned len);

#else

static inline uint32_t ceph_crc32c_aarch64(uint32_t crc, unsigned char const *buffer, unsigned len)
{
	return 0;
}

#endif

#ifdef __cplusplus
}
#endif

#endif
