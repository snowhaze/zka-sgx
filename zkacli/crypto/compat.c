#include <string.h>
#include <time.h>

int _crypto_pwhash_argon2_pick_best_implementation() { return 0; }
int _crypto_stream_chacha20_pick_best_implementation() { return 0; }
void randombytes_stir() { }

__attribute__((noreturn)) extern void sodium_misuse();

__attribute__((weak)) int sgx_read_rand(unsigned char* rand, size_t length);

void randombytes_buf(void* const buff, const size_t size) {
	if (sgx_read_rand(buff, size)) sodium_misuse();
}

void __assert_fail() {
	sodium_misuse();
}

int raise(int s) {
	sodium_misuse();
	return 1;
}

unsigned char* _unprotected_ptr_from_user_ptr(void* const ptr) {
	sodium_misuse();
	return NULL;
}

int nanosleep(const struct timespec* s, struct timespec* i) {
	sodium_misuse();
	return -1;
}
