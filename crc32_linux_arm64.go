// crc32.go - the interface to call the function defined in `libcrc32.a`

package gorados

/*
#cgo LDFLAGS: -L${SRCDIR}/crc32/lib -lcrc32_linux_arm64

#include <stdlib.h>
#include <stdint.h>
uint32_t ceph_crc32c(uint32_t crc, unsigned char const *data, unsigned length);
*/
import "C"

func calculateCrc32(data []byte) uint32 {
	ptr := C.CBytes(data)
	defer C.free(ptr)
	val := C.ceph_crc32c(0, (*C.uchar)(ptr), C.uint(len(data)))
	return uint32(val)
}
