#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>
#include "oram.h"
#include "linear_oram.h"

void test_set_select() {
	size_t data[100];
	for (size_t i = 0; i < 100; i++) {
		oram_set_element(i, 100, sizeof(size_t), &i, data);
	}
	for (size_t i = 0; i < 100 * 2; i++) {
		uint32_t out;
		oram_select_element(i, 100 * 2, sizeof(size_t) / 2, data, &out);
		assert(out == i * ((i + 1) % 2) / 2);
	}
}

void test_64bit_100cell_oram(oram_instance_s* instance) {
	for (size_t i = 0; i < 100; i++) {
		oram_write_element(instance, i, &i);
	}
	for (size_t i = 0; i < 100; i++) {
		uint64_t out;
		oram_read_element(instance, i, &out);
		assert(out == i);
	}
}

void test_linear_oram() {
	oram_instance_s* linear = linear_oram_create(8, 100, false);
	test_64bit_100cell_oram(linear);
	oram_free(linear);
}

void speed_test_linear_oram() {
	clock_t start = clock();
	for (int i = 0; i < 10000; i++) {
		test_linear_oram();
	}
	printf("64bit speed: %f\n", (clock() - start) / (double)CLOCKS_PER_SEC);
}

void test_256bit_1000cell_oram(oram_instance_s* instance) {
	uint8_t data[32] = { 0 };
	uint8_t data2[32] = { 0 };
	for (size_t i = 0; i < 1000; i++) {
		data[0] = i;
		data[1] = i / 256;
		oram_write_element(instance, i, data);
	}
	for (size_t i = 0; i < 1000; i++) {
		uint64_t out;
		oram_read_element(instance, i, data);
		data2[0] = i;
		data2[1] = i / 256;
		assert(!memcmp(data, data2, 32));
	}
}

void speed_test_linear_oram_256bit() {
	oram_instance_s* linear = linear_oram_create(32, 1000, false);
	int itter_count = 100;
	clock_t start = clock();
	for (int i = 0; i < itter_count; i++) {
		test_256bit_1000cell_oram(linear);
	}
	printf("256bit slow speed: %f\n", (clock() - start) / (double)CLOCKS_PER_SEC);
	oram_free(linear);
	linear = linear_oram_create(32, 1000, true);
	start = clock();
	for (int i = 0; i < itter_count; i++) {
		test_256bit_1000cell_oram(linear);
	}
	printf("256bit fast speed: %f\n", (clock() - start) / (double)CLOCKS_PER_SEC);
	oram_free(linear);
}

int main(int argc, char *argv[]) {
	test_set_select();
	test_linear_oram();
	speed_test_linear_oram();
	speed_test_linear_oram_256bit();
	puts("Tests Complete");
}