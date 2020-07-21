#include "linear_oram.h"
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include "../crypto/crypto.h"

#define BYTES_IN_256BITS 32

typedef struct linear_oram {
	oram_instance_s oram;
	size_t element_size;
	size_t element_count;
	void* buffer;
} linear_oram_s;

bool linear_oram_read_element(oram_instance_s* instance, size_t index, void* buffer) {
	linear_oram_s* linear = (linear_oram_s*)instance;
	oram_select_element(index, linear->element_count, linear->element_size, linear->buffer, buffer);
	return true;
}

extern bool linear_oram_read_256bit_element(oram_instance_s* instance, size_t index, void* buffer);

bool linear_oram_write_element(oram_instance_s* instance, size_t index, void* buffer) {
	linear_oram_s* linear = (linear_oram_s*)instance;
	oram_set_element(index, linear->element_count, linear->element_size, buffer, linear->buffer);
	return true;
}

bool linear_oram_free(oram_instance_s* instance) {
	linear_oram_s* linear = (linear_oram_s*)instance;
	clear_buffer(linear->buffer, linear->element_count * linear->element_size);
	free(linear->buffer);
	clear_buffer(linear, sizeof(linear));
	free(linear);
	return true;
}

bool linear_oram_random_init(oram_instance_s* instance) {
	linear_oram_s* linear = (linear_oram_s*)instance;
	random_buf(linear->buffer, linear->element_count * linear->element_size);
	return true;
}

size_t linear_oram_element_size(oram_instance_s* instance) {
	return ((linear_oram_s*)instance)->element_size;
}

size_t linear_oram_element_count(oram_instance_s* instance) {
	return ((linear_oram_s*)instance)->element_count;
}

oram_instance_s* linear_oram_create(size_t element_size, size_t element_count, bool optimized_implementation) {
	linear_oram_s* instance = malloc(sizeof(linear_oram_s));
	if (!instance) return NULL;
	instance->oram.version = ORAM_INSTANCE_S_VERSION;
	if (!optimized_implementation) {
		instance->oram.read_element = linear_oram_read_element;
	} else if (element_size == BYTES_IN_256BITS && element_count <= UINT32_MAX) {
		instance->oram.read_element = linear_oram_read_256bit_element;	
	} else {
		free(instance);
		return NULL;
	}
	instance->oram.write_element = linear_oram_write_element;
	instance->oram.element_size = linear_oram_element_size;
	instance->oram.element_count = linear_oram_element_count;
	instance->oram.free = linear_oram_free;
	instance->oram.random_init = linear_oram_random_init;
	instance->element_size = element_size;
	instance->element_count = element_count;
	
	assert((element_size * element_count) / element_count == element_size);
	instance->buffer = malloc(element_size * element_count);
	if (!instance->buffer) {
		free(instance);
		return NULL;
	}
	return (oram_instance_s*)instance;
}

bool linear_oram_optimized_implementation_available(size_t element_size) {
	return element_size == BYTES_IN_256BITS;
}