#ifndef REVERSE_H
#define REVERSE_H

#include "int_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t reverse_bits(uint32_t v);
extern uint32_t reverse_nibbles(uint32_t retval);

#ifdef __cplusplus
}
#endif

#endif    
