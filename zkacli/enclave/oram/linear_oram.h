#ifndef LINEAR_ORAM_H
#define LINEAR_ORAM_H

#include "oram.h"

oram_instance_s* linear_oram_create(size_t element_size, size_t element_count, bool optimized_implementation);

bool linear_oram_optimized_implementation_available(size_t element_size);

#endif