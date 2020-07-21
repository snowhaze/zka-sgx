#ifndef ENCLAVE_H
#define ENCLAVE_H

#include <stdint.h>
#include <stdbool.h>
#include <sgx_report.h>
#include <sgx_tseal.h>
#include <sodium.h>
#include "crypto/crypto.h"

#define STATIC_ASSERT(c) _Static_assert(c, #c)

#define SEPARATOR ((char)';')

#define BASE64_LEN(s) (sodium_base64_ENCODED_LEN(s, sodium_base64_VARIANT_ORIGINAL) - 1)

#define TOKEN_SIZE 32

#define ENCODED_TOKEN_SIZE BASE64_LEN(TOKEN_SIZE)
#define SEALED_KEYS_SIZE (sizeof(key_buf_s) + sizeof(sgx_sealed_data_t))

#define TOKEN_COUNT(pk, reserve, tokens, numerator, denominator) (tokens + (reserve + pk) * numerator / denominator)
#define TOKEN_COUNT_OVERFLOW(pk, reserve, tokens, numerator, denominator) (denominator == 0 || (reserve + pk) < pk || (reserve + pk) * numerator / numerator < reserve + pk || tokens + (reserve + pk) * numerator / denominator < tokens)

#define RESERVE_BUFFER_SIZE(tokens) ((size_t)tokens * TOKEN_SIZE + MAC_SIZE)
#define RESULT_BUFFER_SIZE(tokens) ((((size_t)tokens - 1) * sizeof(SEPARATOR)) + (size_t)tokens * ENCODED_TOKEN_SIZE + SIGNATURE_SIZE + PUBLIC_KEY_SIZE + MAC_SIZE)

#define SIZE_CHECKS() STATIC_ASSERT(PUBLIC_KEY_SIZE == sizeof(pub_key_s) && SIGN_PRIVATE_KEY_SIZE + SEAL_KEY_SIZE == sizeof(key_buf_s) && 6 * 4 + 8 + 2 * SIGN_PUBLIC_KEY_SIZE == sizeof(zka_report_s) && ENCODED_TOKEN_SIZE > TOKEN_SIZE && ENCODED_TOKEN_SIZE == 44 && TOKEN_SIZE == crypto_kdf_KEYBYTES)

#define ZKA_OUTPUT_TYPE_RAW ((zka_output_type_t)0)
#define ZKA_OUTPUT_TYPE_HASH ((zka_output_type_t)1)

#define ZKA_OUTPUT_SIZE(type, count) ((size_t)count * (type == ZKA_OUTPUT_TYPE_RAW ? TOKEN_SIZE : \
												((type & ZKA_OUTPUT_TYPE_HASH) ? TOKEN_SIZE : 0)))

#define ZKA_OUTPUT_TYPE_VALID(type) (type < ((zka_output_type_t)2))

typedef uint64_t zka_output_type_t;
#define ZKA_OUTPUT_TYPE_RAW ((zka_output_type_t)0)
#define ZKA_OUTPUT_TYPE_HASHED ((zka_output_type_t)1)

typedef enum {
	ENCLAVE_NO_ERROR = 0,
	ENCLAVE_ARGUMENT_ERROR,
	ENCLAVE_OOM_ERROR,
	ENCLAVE_SDK_ERROR,
	ENCLAVE_CRYPTO_ERROR,
	ENCLAVE_ORAM_ERROR,
} enclave_error_t;

typedef struct key_buf {
	uint8_t				seal[SEAL_KEY_SIZE];
	uint8_t				sign[SIGN_PRIVATE_KEY_SIZE];
} key_buf_s;

typedef struct zka_report {
	uint32_t			version;
	uint32_t			reserve;
	uint32_t			pks;
	uint32_t			tokens_per_set;
	uint32_t			oversize_numerator;
	uint32_t			oversize_denominator;
	zka_output_type_t	output_type;
	uint8_t				primary_sign[SIGN_PUBLIC_KEY_SIZE];
	uint8_t				seccondary_sign[SIGN_PUBLIC_KEY_SIZE];
} zka_report_s;

typedef struct reserve_buf {
	uint8_t min[RESERVE_BUFFER_SIZE(1)];
	uint8_t rest[];
} reserve_buf_s;

typedef struct result_buf {
	uint8_t min[RESULT_BUFFER_SIZE(1)];
	uint8_t rest[];
} result_buf_s;

#endif // ifndef ENCLAVE_H
