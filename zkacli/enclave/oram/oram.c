#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include "oram.h"
#include "../crypto/crypto.h"

bool oram_read_element(oram_instance_s* instance, size_t index, void* buffer) {
	return instance->read_element(instance, index, buffer);
}

bool oram_write_element(oram_instance_s* instance, size_t index, void* buffer) {
	return instance->write_element(instance, index, buffer);
}

bool oram_free(oram_instance_s* instance) {
	return instance->free(instance);
}

bool oram_random_init(oram_instance_s* instance) {
	if (instance->random_init) return instance->random_init(instance);
	size_t size = oram_element_size(instance);
	uint8_t* data = malloc(size);
	if (!data) return false;
	size_t count = oram_element_count(instance);
	bool success = false;
	for (size_t i = 0; i < count; i++) {
		random_buf(data, size);
		if (!oram_write_element(instance, i, data)) goto fail;
	}
	success = true;
fail:
	clear_buffer(data, oram_element_size(instance));
	free(data);
	return success;
}

size_t oram_element_size(oram_instance_s* instance) {
	return instance->element_size(instance);
}

size_t oram_element_count(oram_instance_s* instance) {
	return instance->element_count(instance);
}

size_t oram_prefix_size_for_version(size_t version) {
	(void)version;
	assert(version == ORAM_INSTANCE_S_VERSION);
	return sizeof(oram_instance_s);
}

void oram_select_element(size_t index, size_t count, size_t element_size, void* in_buffer, void* out_buffer) {
	assert((count * element_size) / element_size == count);
	assert(index < count);
	uint8_t* in = in_buffer;
	uint8_t* out = out_buffer;
	memset(out, 0, element_size);
	for (size_t i = 0; i < count; i++) {
		uint64_t mask = i ^ index;
		mask = (uint64_t)((uint32_t)mask | (uint32_t)(mask >> 32)) - 1;
		mask = (int64_t)mask >> 63;
		uint8_t mask_byte = mask;
		size_t j = 0;
		for (; j < element_size / 8; j++) {
			((uint64_t*)out)[j] = (((uint64_t*)(in + i * element_size))[j] & mask) | ((uint64_t*)out)[j];
		}
		j *= 8;
		for (; j < element_size; j++) {
			out[j] = (in[i * element_size + j] & mask_byte) | out[j];
		}
	}
}

void oram_set_element(size_t index, size_t count, size_t element_size, void* in_buffer, void* out_buffer) {
	assert((count * element_size) / element_size == count);
	assert(index < count);
	uint8_t* in = in_buffer;
	uint8_t* out = out_buffer;
	for (size_t i = 0; i < count; i++) {
		uint64_t mask = i ^ index;
		mask = (uint64_t)((uint32_t)mask | (uint32_t)(mask >> 32)) - 1;
		mask = (int64_t)mask >> 63;
		uint8_t mask_byte = mask;
		size_t j = 0;
		for (; j < element_size / 8; j++) {
			((uint64_t*)(out + i * element_size))[j] = (((uint64_t*)in)[j] & mask) | (((uint64_t*)(out + i * element_size))[j] & ~mask);
		}
		j *= 8;
		for (; j < element_size; j++) {
			out[i * element_size + j] = (in[j] & mask_byte) | (out[i * element_size + j] & ~mask_byte);
		}
	}
}