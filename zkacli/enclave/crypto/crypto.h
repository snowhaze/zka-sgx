#ifndef CRYPTO_H
#define CRYPTO_H

#include <sodium.h>

#define NONCE_SIZE crypto_secretbox_NONCEBYTES
#define PUBLIC_KEY_SIZE crypto_box_PUBLICKEYBYTES
#define SIGN_PRIVATE_KEY_SIZE crypto_sign_SECRETKEYBYTES
#define SIGN_PUBLIC_KEY_SIZE crypto_sign_PUBLICKEYBYTES
#define SEAL_KEY_SIZE crypto_secretbox_KEYBYTES
#define MAC_SIZE crypto_secretbox_MACBYTES
#define SIGNATURE_SIZE crypto_sign_BYTES

typedef struct pub_key {
	uint8_t key[PUBLIC_KEY_SIZE];
} pub_key_s;

void clear_buffer(void* buffer, size_t size);
int const_memcmp(void* a, void* b, size_t size);
int asym_seal(void* dst, void* src, pub_key_s* key, size_t cleartext_size);
int sign(void* dst, void* src, uint8_t* key, size_t cleartext_size);
int gen_sign_keys(uint8_t* pk, uint8_t* sk);
int hash(void* dest, size_t dest_size, void* src, size_t src_size);
int sym_seal(void* dst, void* src,  uint8_t* key, uint32_t i, size_t cleartext_size);
int sym_unseal(void* dst, void* src, uint8_t* key, uint32_t i, size_t cleartext_size);
void random_buf(uint8_t* buff, size_t size);

#endif