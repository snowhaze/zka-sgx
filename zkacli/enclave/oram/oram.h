#ifndef ORAM_H
#define ORAM_H

#include <string.h>
#include <stdbool.h>

#define ORAM_INSTANCE_S_VERSION 1

typedef struct oram_instance oram_instance_s;

struct oram_instance {
	size_t version;
	bool (*read_element)(oram_instance_s* instance, size_t index, void* buffer);
	bool (*write_element)(oram_instance_s* instance, size_t index, void* buffer);
	size_t (*element_size)(oram_instance_s* instance);
	size_t (*element_count)(oram_instance_s* instance);
	bool (*free)(oram_instance_s* instance);
	bool (*random_init)(oram_instance_s* instance);
};

bool oram_read_element(oram_instance_s* instance, size_t index, void* buffer);
bool oram_write_element(oram_instance_s* instance, size_t index, void* buffer);

bool oram_random_init(oram_instance_s* instance);
bool oram_free(oram_instance_s* instance);

size_t oram_element_size(oram_instance_s* instance);
size_t oram_element_count(oram_instance_s* instance);

void oram_select_element(size_t index, size_t count, size_t element_size, void* in_buffer, void* out_buffer);
void oram_set_element(size_t index, size_t count, size_t element_size, void* in_buffer, void* out_buffer);

size_t oram_prefix_size_for_version(size_t version);

#endif