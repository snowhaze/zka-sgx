#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include <string.h>
#include <assert.h>
#include "enclave.h"
#include "oram/linear_oram.h"
#include "crypto/crypto.h"

#define ABORT(sensbufs, error) return sensbufs_pop_all(sensbufs), error

typedef struct {
	size_t size;
	void* buffer;
	void (*free)(void*);
} sensbuf_s;

typedef struct {
	sensbuf_s list[10];
	size_t entries;
} sensbuf_list_s;

typedef struct token {
	uint8_t token[TOKEN_SIZE];
} token_s;

static void sensbufs_push(sensbuf_list_s* list, void* buffer, size_t size, void (*free_fn)(void*)) {
	assert(list->entries < 10);
	list->list[list->entries].buffer = buffer;
	list->list[list->entries].size = size;
	list->list[list->entries].free = free_fn;
	list->entries++;
}

static void sensbufs_pop(sensbuf_list_s* list) {
	assert(list->entries);
	list->entries--;
	clear_buffer(list->list[list->entries].buffer, list->list[list->entries].size);
	if (list->list[list->entries].free) list->list[list->entries].free(list->list[list->entries].buffer);
	list->list[list->entries] = (sensbuf_s){ 0 };
}

static void sensbufs_pop_n(sensbuf_list_s* list, size_t count) {
	assert(count <= list->entries);
	for (size_t i = 0; i < count; i++) sensbufs_pop(list);
}

static void sensbufs_pop_all(sensbuf_list_s* list) {
	sensbufs_pop_n(list, list->entries);
}

static bool is_duplicate(token_s* buffer, uint32_t count, token_s* token) {
	for (uint32_t i = 0; i < count; i++) if (!const_memcmp(buffer + i, token, sizeof(token_s))) return true;
	return false;
}

static bool select_unique_token(oram_instance_s* oram, token_s* buffer, uint32_t offset) {
	size_t token_count = oram_element_count(oram);
	assert(token_count);
	assert(sizeof(token_s) == oram_element_size(oram));
	do {
		uint32_t index;
		uint32_t ignore = (1 + ~token_count) % token_count;
		do {
			random_buf((uint8_t*)&index, sizeof(index));
		} while (index < ignore);
		index = index % token_count;
		if (!oram_read_element(oram, index, buffer + offset)) return false;
	} while (is_duplicate(buffer, offset, buffer + offset));
	return true;
}

static void encode(uint8_t* buffer, uint32_t tokens_per_set) {
	uint8_t token[ENCODED_TOKEN_SIZE + 1];
	for (uint32_t i = 0; i < tokens_per_set; i++) {
		uint8_t* dest = buffer + (tokens_per_set - 1 - i) * (ENCODED_TOKEN_SIZE + sizeof(SEPARATOR));
		uint8_t* src = buffer + (tokens_per_set - 1 - i) * TOKEN_SIZE;
		sodium_bin2base64((char*)token, ENCODED_TOKEN_SIZE + 1, src, TOKEN_SIZE, sodium_base64_VARIANT_ORIGINAL);
		if (i) token[ENCODED_TOKEN_SIZE] = SEPARATOR;
		memcpy(dest, token, ENCODED_TOKEN_SIZE + (i ? 1 : 0));
	}
	clear_buffer(token, sizeof(token));
}

extern enclave_error_t generate(
	pub_key_s*			pks,			/* user_check */
	uint32_t			pk_count,
	uint32_t			reserve_count,
	uint32_t			tokens_per_set,
	uint32_t			oversize_numerator,
	uint32_t			oversize_denominator,
	sgx_target_info_t	dest,
	sgx_report_t*		report,			/* out, count=1 */
	zka_report_s*		zka_report,		/* out, count=1 */
	reserve_buf_s*		reserve_buffer,	/* user_check */
	result_buf_s*		result_buffer,	/* user_check */
	void*				output,			/* user_check */
	zka_output_type_t	output_type,
	uint32_t			sealed_size,
	sgx_sealed_data_t*	sealed_keys		/* out, count=1, size=sealed_size */
) {
	SIZE_CHECKS();
	// Ensure everything fits into 32 bits
	if (pk_count > 1000000) return ENCLAVE_ARGUMENT_ERROR;
	if (reserve_count > 1000000) return ENCLAVE_ARGUMENT_ERROR;
	if (tokens_per_set > 1000) return ENCLAVE_ARGUMENT_ERROR;

	// Using enclave has no acctual benefit
	if (pk_count + reserve_count < 2) return ENCLAVE_ARGUMENT_ERROR;

	if (!oversize_denominator || !oversize_numerator) return ENCLAVE_ARGUMENT_ERROR;
	if (TOKEN_COUNT_OVERFLOW(pk_count, reserve_count, tokens_per_set, oversize_numerator, oversize_denominator)) return ENCLAVE_ARGUMENT_ERROR;

	size_t token_cnt = TOKEN_COUNT(pk_count, reserve_count, tokens_per_set, oversize_numerator, oversize_denominator);

	if (!ZKA_OUTPUT_TYPE_VALID(output_type)) return ENCLAVE_ARGUMENT_ERROR;
	if (ZKA_OUTPUT_SIZE(output_type, token_cnt) / ZKA_OUTPUT_SIZE(output_type, 1) != token_cnt) return ENCLAVE_ARGUMENT_ERROR;

	// Ensure parameters are sensible
	if (!pks || !report || !zka_report || !reserve_buffer || !result_buffer || !output || !sealed_keys) return ENCLAVE_ARGUMENT_ERROR;
	if (!sgx_is_outside_enclave(pks, sizeof(pub_key_s) * pk_count)) return ENCLAVE_ARGUMENT_ERROR;
	if (!sgx_is_outside_enclave(reserve_buffer, RESERVE_BUFFER_SIZE(tokens_per_set) * reserve_count)) return ENCLAVE_ARGUMENT_ERROR;
	if (!sgx_is_outside_enclave(result_buffer, RESULT_BUFFER_SIZE(tokens_per_set) * pk_count)) return ENCLAVE_ARGUMENT_ERROR;
	if (!sgx_is_outside_enclave(output, ZKA_OUTPUT_SIZE(output_type, token_cnt))) return ENCLAVE_ARGUMENT_ERROR;
	if (sealed_size != sgx_calc_sealed_data_size(0, sizeof(key_buf_s)) || sealed_size == 0xFFFFFFFF) return ENCLAVE_ARGUMENT_ERROR;
	if (!tokens_per_set) return ENCLAVE_ARGUMENT_ERROR;

	zka_report->version = 1;
	zka_report->reserve = reserve_count;
	zka_report->pks = pk_count;
	zka_report->tokens_per_set = tokens_per_set;
	zka_report->oversize_numerator = oversize_numerator;
	zka_report->oversize_denominator = oversize_denominator;
	zka_report->output_type = output_type;

	sgx_status_t result;
	sensbuf_list_s sensbufs = { 0 };

	key_buf_s keys;
	uint8_t primary_sign_key[SIGN_PRIVATE_KEY_SIZE] = { 0 };
	sensbufs_push(&sensbufs, &keys, sizeof(keys), NULL);
	sensbufs_push(&sensbufs, &primary_sign_key, sizeof(primary_sign_key), NULL);
	STATIC_ASSERT(sizeof(keys.seal) == SEAL_KEY_SIZE);
	STATIC_ASSERT(sizeof(keys.sign) == SIGN_PRIVATE_KEY_SIZE);

	random_buf(keys.seal, sizeof(keys.seal));
	if (gen_sign_keys(zka_report->primary_sign, primary_sign_key)) ABORT(&sensbufs, ENCLAVE_CRYPTO_ERROR);
	if (gen_sign_keys(zka_report->seccondary_sign, keys.sign)) ABORT(&sensbufs, ENCLAVE_CRYPTO_ERROR);

	STATIC_ASSERT(RESULT_BUFFER_SIZE(1) >= RESERVE_BUFFER_SIZE(1));
	result_buf_s* next_result = malloc(RESULT_BUFFER_SIZE(tokens_per_set));
	if (!next_result) ABORT(&sensbufs, ENCLAVE_OOM_ERROR);
	sensbufs_push(&sensbufs, next_result, RESULT_BUFFER_SIZE(tokens_per_set), free);

	size_t sign_msg_len = tokens_per_set * (ENCODED_TOKEN_SIZE + sizeof(SEPARATOR)) - sizeof(SEPARATOR) + PUBLIC_KEY_SIZE + MAC_SIZE;
	uint8_t* encrypted = malloc(sign_msg_len);
	if (!encrypted) ABORT(&sensbufs, ENCLAVE_OOM_ERROR);
	sensbufs_push(&sensbufs, encrypted, sign_msg_len, free);

	oram_instance_s* oram = linear_oram_create(32, token_cnt, true);
	if (!oram) ABORT(&sensbufs, ENCLAVE_OOM_ERROR);
	sensbufs_push(&sensbufs, oram, 0, (void(*)(void*))oram_free);
	if (!oram_random_init(oram)) ABORT(&sensbufs, ENCLAVE_ORAM_ERROR);

	pub_key_s current_pk;
	for (uint32_t i = 0; i < pk_count; i++) {
		current_pk = pks[i];
		for (uint32_t j = 0; j < tokens_per_set; j++) {
			if (!select_unique_token(oram, (token_s*)next_result, j)) ABORT(&sensbufs, ENCLAVE_ORAM_ERROR);
		}
		STATIC_ASSERT(RESULT_BUFFER_SIZE(1) == ENCODED_TOKEN_SIZE + PUBLIC_KEY_SIZE + MAC_SIZE + SIGNATURE_SIZE);
		encode((uint8_t*)next_result, tokens_per_set);
		if (asym_seal(encrypted, next_result, &current_pk, tokens_per_set * (ENCODED_TOKEN_SIZE + sizeof(SEPARATOR)) - sizeof(SEPARATOR))) ABORT(&sensbufs, ENCLAVE_CRYPTO_ERROR);
		if (sign(((uint8_t*)result_buffer) + i * RESULT_BUFFER_SIZE(tokens_per_set), encrypted, (uint8_t*)&primary_sign_key, sign_msg_len)) ABORT(&sensbufs, ENCLAVE_CRYPTO_ERROR);
	}

	for (uint32_t i = 0; i < reserve_count; i++) {
		for (uint32_t j = 0; j < tokens_per_set; j++) {
			if (!select_unique_token(oram, (token_s*)next_result, j)) ABORT(&sensbufs, ENCLAVE_ORAM_ERROR);
		}
		STATIC_ASSERT(RESERVE_BUFFER_SIZE(1) == TOKEN_SIZE + MAC_SIZE);
		uint8_t* dst = ((uint8_t*)reserve_buffer) + i * RESERVE_BUFFER_SIZE(tokens_per_set);
		if (sym_seal(dst, next_result, keys.seal, i, tokens_per_set * sizeof(token_s))) ABORT(&sensbufs, ENCLAVE_CRYPTO_ERROR);
	}

	uint8_t token[TOKEN_SIZE];
	sensbufs_push(&sensbufs, token, TOKEN_SIZE, NULL);
	for (size_t i = 0; i < token_cnt; i++) {
		if (!oram_read_element(oram, i, token)) ABORT(&sensbufs, ENCLAVE_ORAM_ERROR);
		if (output_type == ZKA_OUTPUT_TYPE_RAW) {
			memcpy(output, token, TOKEN_SIZE);
		} else {
			if (output_type & ZKA_OUTPUT_TYPE_HASH) {
				if (crypto_kdf_derive_from_key(output, ZKA_OUTPUT_SIZE(ZKA_OUTPUT_TYPE_HASH, 1), 1, "hashtokn", token)) ABORT(&sensbufs, ENCLAVE_CRYPTO_ERROR);
			}
		}
		output += ZKA_OUTPUT_SIZE(output_type, 1);
	}

	result = sgx_seal_data(0, NULL, sizeof(key_buf_s), (uint8_t*)&keys, sealed_size, sealed_keys);
	if (result != SGX_SUCCESS) ABORT(&sensbufs, ENCLAVE_SDK_ERROR);

	sgx_report_data_t report_data;
	report_data.d[0] = 1;
	if (hash(report_data.d + 1, sizeof(report_data.d) - 1, zka_report, sizeof(*zka_report))) ABORT(&sensbufs, ENCLAVE_CRYPTO_ERROR);
	sensbufs_pop_all(&sensbufs);
	return sgx_create_report(&dest, &report_data, report) == SGX_SUCCESS ? ENCLAVE_NO_ERROR : ENCLAVE_SDK_ERROR;
}

extern enclave_error_t reencrypt(
	pub_key_s			pk,
	uint32_t			index,
	uint32_t			tokens_per_set,
	size_t				reserve_buffer_size,
	size_t				result_buffer_size,
	uint32_t			sealed_size,
	sgx_sealed_data_t*	sealed_keys,/* in, count=1, size=sealed_size */
	reserve_buf_s*		reserve_buf,/* in, count=1, size=reserve_buffer_size */
	result_buf_s*		result		/* out, count=1, size=result_buffer_size */
) {
	SIZE_CHECKS();
	sensbuf_list_s sensbufs = { 0 };
	if (!sealed_keys || !reserve_buf || !result) ABORT(&sensbufs, ENCLAVE_ARGUMENT_ERROR);
	if (reserve_buffer_size != RESERVE_BUFFER_SIZE(tokens_per_set)) ABORT(&sensbufs, ENCLAVE_ARGUMENT_ERROR);
	if (result_buffer_size != RESULT_BUFFER_SIZE(tokens_per_set)) ABORT(&sensbufs, ENCLAVE_ARGUMENT_ERROR);
	if (sealed_size != sgx_calc_sealed_data_size(0, sizeof(key_buf_s)) || sealed_size == 0xFFFFFFFF) ABORT(&sensbufs, ENCLAVE_ARGUMENT_ERROR);
	if (!tokens_per_set) ABORT(&sensbufs, ENCLAVE_ARGUMENT_ERROR);

	key_buf_s keys;
	uint32_t keys_size = sizeof(key_buf_s);
	uint32_t ad_size = 0;
	sensbufs_push(&sensbufs, &keys, sizeof(keys), NULL);
	if (sgx_unseal_data(sealed_keys, NULL, &ad_size, (uint8_t*)&keys, &keys_size) != SGX_SUCCESS) ABORT(&sensbufs, ENCLAVE_SDK_ERROR);
	if (ad_size != 0 || keys_size != sizeof(key_buf_s)) ABORT(&sensbufs, ENCLAVE_ARGUMENT_ERROR);

	size_t sign_msg_len = tokens_per_set * (ENCODED_TOKEN_SIZE + sizeof(SEPARATOR)) - sizeof(SEPARATOR) + PUBLIC_KEY_SIZE + MAC_SIZE;
	uint8_t* encrypted = malloc(sign_msg_len);
	if (!encrypted) ABORT(&sensbufs, ENCLAVE_OOM_ERROR);
	sensbufs_push(&sensbufs, encrypted, sign_msg_len, free);

	result_buf_s* temp_result = malloc(result_buffer_size);
	if (!temp_result) ABORT(&sensbufs, ENCLAVE_OOM_ERROR);
	sensbufs_push(&sensbufs, temp_result, result_buffer_size, free);
	if (sym_unseal(temp_result, reserve_buf, keys.seal, index, tokens_per_set * sizeof(token_s))) ABORT(&sensbufs, ENCLAVE_CRYPTO_ERROR);
	encode((uint8_t*)temp_result, tokens_per_set);
	if (asym_seal(encrypted, temp_result, &pk, tokens_per_set * (ENCODED_TOKEN_SIZE + sizeof(SEPARATOR)) - sizeof(SEPARATOR))) ABORT(&sensbufs, ENCLAVE_CRYPTO_ERROR);
	if (sign(result, encrypted, (uint8_t*)&keys.sign, sign_msg_len)) ABORT(&sensbufs, ENCLAVE_CRYPTO_ERROR);
	sensbufs_pop_all(&sensbufs);
	return ENCLAVE_NO_ERROR;
}
