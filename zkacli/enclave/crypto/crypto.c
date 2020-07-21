#include "crypto.h"
#include <assert.h>
#include <string.h>

void clear_buffer(void* buffer, size_t size) {
	errno_t result = memset_s(buffer, size, 0, size);
	(void)result;
	assert(result == 0);
}

int const_memcmp(void* a, void* b, size_t size) {
	return sodium_memcmp(a, b, size);
}

int asym_seal(void* dst, void* src, pub_key_s* key, size_t cleartext_size) {
	return crypto_box_seal(dst, src, cleartext_size, (uint8_t*)key);
}

int sign(void* dst, void* src, uint8_t* key, size_t cleartext_size) {
	return crypto_sign(dst, NULL, src, cleartext_size, key);
}

int gen_sign_keys(uint8_t* pk, uint8_t* sk) {
	return crypto_sign_keypair(pk, sk);
}

int hash(void* dest, size_t dest_size, void* src, size_t src_size) {
	return crypto_generichash(dest, dest_size, src, src_size, NULL, 0);
}

int sym_seal(void* dst, void* src,  uint8_t* key, uint32_t i, size_t cleartext_size) {
	uint8_t nonce[NONCE_SIZE] = { 0 };
	((uint32_t*)nonce)[0] = i;
	return crypto_secretbox_easy(dst, src, cleartext_size, nonce, key);
}

int sym_unseal(void* dst, void* src, uint8_t* key, uint32_t i, size_t cleartext_size) {
	uint8_t nonce[NONCE_SIZE] = { 0 };
	((uint32_t*)nonce)[0] = i;
	return crypto_secretbox_open_easy(dst, src, cleartext_size + MAC_SIZE, nonce, key);
}

void random_buf(uint8_t* buff, size_t size) {
	randombytes_buf(buff, size);
}