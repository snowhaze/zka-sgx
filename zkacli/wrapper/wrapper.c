#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <sgx_uae_service.h>
#include <sodium.h>
#include "enclave.h"
#include "enclave_u.h"

#define ENCLAVE "enclave.signed.so"

#define UNUSED(x) (void)(x)

static const char* name;

__attribute__((__noreturn__)) void fail(char* error) {
	puts("ERROR");
	puts(error);
	exit(1);
}

__attribute__((__noreturn__)) void fail_usage() {
	int size = snprintf(NULL, 0, "Incorrect Usage. See `%s help' for help.", name);
	if (size < 0) fail("Internal Error");
	char* error = malloc(size + 1);
	if (!error) fail("Out of Memory");
	if (snprintf(error, size + 1, "Incorrect Usage. See `%s help' for help.", name) < 0) fail("Internal Error");
	fail(error);
	// cannot free(error) since fail() doesn't return
}

void printbuf(void* buf, size_t size) {
	uint8_t b64[BASE64_LEN(size) + 1];
	puts((char*)sodium_bin2base64((char*)b64, sizeof(b64), buf, size, sodium_base64_VARIANT_ORIGINAL));
}

void parse_buffer(void* buffer, size_t size, char* input) {
	size_t real_size;
	size_t input_len = strlen(input);
	if (input_len != BASE64_LEN(size)) fail_usage();
	int result = sodium_base642bin(buffer, size, input, input_len, NULL, &real_size, NULL, sodium_base64_VARIANT_ORIGINAL);
	if (result) fail_usage();
	if (size != real_size) fail_usage();
}

uint32_t parse_num(char* input) {
	if (!*input) fail_usage();
	for (char*c = input; *c; c++) if (!isdigit(*c)) fail_usage();
	unsigned long result = strtoul(input, NULL, 10);
	if (result > 1000000) fail_usage();
	return result;
}

double parse_double(char* input) {
	size_t length = strlen(input);
	if (length > 8) fail_usage();
	int dot_position = -1;
	for (int i = 0; input[i]; i++) {
		if (input[i] == '.' && dot_position >= 0) fail_usage();
		else if (input[i] == '.') dot_position = i;
		else if (!isdigit(input[i])) fail_usage();
	}
	if (dot_position < 0) dot_position = length;
	if (length > (size_t)dot_position + 4) fail_usage();
	if (dot_position > 4 || dot_position <= 0) fail_usage();
	if (dot_position == 4 && strncmp(input, "1000", 4)) fail_usage();
	return strtod(input, NULL);
}

void read_buffer(void* buffer, size_t size) {
	char* line = NULL;
	size_t n = 0;
	ssize_t length = 0;
	if ((length = getline(&line, &n, stdin)) < 0) fail_usage();
	if (length && line[length - 1] == '\n') line[--length] = '\0';
	parse_buffer(buffer, size, line);
	free(line);
}

void generate_cmd(int argc, char* argv[]) {
	if (argc != 7) fail_usage();

	uint32_t pks_count = parse_num(argv[2]);
	uint32_t reserve_count = parse_num(argv[3]);
	uint32_t tokens_per_set = parse_num(argv[6]);
	double oversize = parse_double(argv[4]);
	uint32_t denominator = 1000;
	uint32_t numerator = oversize * denominator + 0.5;
	if (!tokens_per_set) fail("Token Sets must Contain Tokens");
	if (tokens_per_set > 1000) fail("Token Sets too Large");
	if (pks_count > 1000000) fail("Too many Public Keys");
	if (reserve_count > 1000000) fail("Too many Reserve Tokens");

	zka_output_type_t output_type;
	if (!strcmp(argv[5], "raw")) output_type = ZKA_OUTPUT_TYPE_RAW;
	else if (!strcmp(argv[5], "hash")) output_type = ZKA_OUTPUT_TYPE_HASH;
	else fail_usage();

	pub_key_s* pks = malloc(pks_count * sizeof(pub_key_s));
	if (!pks) fail("Out of Memory");
	for (uint32_t i = 0; i < pks_count; i++) read_buffer(pks + i, sizeof(pub_key_s));

	uint32_t egid;
	if (sgx_get_extended_epid_group_id(&egid) != SGX_SUCCESS) fail("Failed to Determine EPID Group");
	if (egid != 0) fail("Unsupported Extended EPID Group");
	sgx_target_info_t target_info;
	sgx_epid_group_id_t gid;
	if (sgx_init_quote(&target_info, &gid) != SGX_SUCCESS) fail("Failed to Obtain QE Info");

	sgx_enclave_id_t enclave_id;
	sgx_status_t result;
	enclave_error_t error;
	result = sgx_create_enclave(ENCLAVE, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);
	if (result != SGX_SUCCESS) fail("Failed to Launch Enclave");
	sgx_report_t report;
	zka_report_s zka_report;
	reserve_buf_s* reserve = malloc(reserve_count * RESERVE_BUFFER_SIZE(tokens_per_set));
	if (!reserve) fail("Out of Memory");
	result_buf_s* resultbuf = malloc(pks_count * RESULT_BUFFER_SIZE(tokens_per_set));
	if (!resultbuf) fail("Out of Memory");
	size_t token_count = TOKEN_COUNT(pks_count, reserve_count, tokens_per_set, numerator, denominator);
	void* output = malloc(ZKA_OUTPUT_SIZE(output_type, token_count));
	if (!output) fail("Out of Memory");
	sgx_sealed_data_t* keys = malloc(SEALED_KEYS_SIZE);
	if (!keys) fail("Out of Memory");

	result = generate(enclave_id, &error, pks, pks_count, reserve_count, tokens_per_set, numerator, denominator, target_info, &report, &zka_report, reserve, resultbuf, output, output_type, SEALED_KEYS_SIZE, keys);
	if (result != SGX_SUCCESS) fail("Failed to Run Enclave");
	switch (error) {
		case ENCLAVE_NO_ERROR:			break;
		case ENCLAVE_ARGUMENT_ERROR:	fail("Invalid Arguments");
		case ENCLAVE_OOM_ERROR:			fail("EPC Memory Full");
		case ENCLAVE_SDK_ERROR:			fail("SGX SDK Error");
		case ENCLAVE_CRYPTO_ERROR:		fail("Cryptography Failed");
		case ENCLAVE_ORAM_ERROR:		fail("Failed to Hide Memory Access Pattern");
		default:						fail("Unexpected Error");
	}
	if (error) fail("Failed to Encrypt Tokens");

	uint32_t quote_size;
	result = sgx_calc_quote_size(NULL, 0, &quote_size);
	if (result != SGX_SUCCESS) fail("Failed to Calculate Quote Size");

#if SGX_DEBUG_FLAG
	sgx_spid_t spid = {{ 0x62, 0x9A, 0xE6, 0xC9, 0xFB, 0xF2, 0x27, 0x09, 0xE9, 0x79, 0x09, 0x0D, 0x48, 0x96, 0x49, 0xC0 }};
#else
	sgx_spid_t spid = {{ 0xBD, 0x63, 0x69, 0xAF, 0xFD, 0xEC, 0xE0, 0x86, 0x8C, 0xAF, 0x35, 0xB0, 0x9D, 0x28, 0x84, 0x1B }};
#endif
	sgx_quote_t* quote = malloc(quote_size);
	if (!quote) fail("Out of Memory");
	while (true) {
		result = sgx_get_quote(&report, SGX_LINKABLE_SIGNATURE, &spid, NULL, NULL, 0, NULL, quote, quote_size);
		if (result != SGX_ERROR_BUSY) break;
		sleep(1);
	}
	if (result != SGX_SUCCESS) fail("Failed to Obtain Quote");

	puts("OK");

	for (uint32_t i = 0; i < pks_count; i++) printbuf((uint8_t*)resultbuf + i * RESULT_BUFFER_SIZE(tokens_per_set), RESULT_BUFFER_SIZE(tokens_per_set));
	for (uint32_t i = 0; i < reserve_count; i++) printbuf((uint8_t*)reserve + i * RESERVE_BUFFER_SIZE(tokens_per_set), RESERVE_BUFFER_SIZE(tokens_per_set));

	printbuf(keys, SEALED_KEYS_SIZE);
	printbuf(&zka_report, sizeof(zka_report));
	printbuf(quote, quote_size);
	char print_buffer[BASE64_LEN(ZKA_OUTPUT_SIZE(output_type, 1)) + 4 * 64 + 64];
	void* source = output;
	for (size_t i = 0; i < TOKEN_COUNT(pks_count, reserve_count, tokens_per_set, numerator, denominator); i++) {
		if (output_type == ZKA_OUTPUT_TYPE_RAW) {
			size_t size = ZKA_OUTPUT_SIZE(output_type, 1);
			printbuf(source,  size);
			source += size;
		} else {
			char* destination = print_buffer;
			size_t dest_size = sizeof(print_buffer);
			for (zka_output_type_t type = 1; ZKA_OUTPUT_TYPE_VALID(type); type <<= 1) {
				if (!(output_type & type)) continue;
				size_t size = ZKA_OUTPUT_SIZE(type, 1);
				if (!sodium_bin2base64(destination, dest_size, source, size, sodium_base64_VARIANT_ORIGINAL)) fail("Failed to Print Result");
				source += size;
				destination += BASE64_LEN(size) + 1;
				dest_size -= BASE64_LEN(size) + 1;
				*(destination - 1) = ',';
			}
			*(destination - 1) = '\0';
			puts(print_buffer);
		}
	}

	free(pks);
	free(reserve);
	free(resultbuf);
	free(output);
	free(keys);
	free(quote);
}

void reencrypt_cmd(int argc, char* argv[]) {
	if (argc != 7) fail_usage();

	uint32_t index = parse_num(argv[5]);
	uint32_t tokens_per_set = parse_num(argv[6]);
	if (!tokens_per_set) fail("Token Sets must Contain Tokens");
	result_buf_s* result_buffer = malloc(RESULT_BUFFER_SIZE(tokens_per_set));
	if (!result_buffer) fail("Out of Memory");
	reserve_buf_s* reserve = malloc(RESERVE_BUFFER_SIZE(tokens_per_set));
	if (!reserve) fail("Out of Memory");
	sgx_sealed_data_t* keys = malloc(SEALED_KEYS_SIZE);
	if (!keys) fail("Out of Memory");
	pub_key_s pk;
	parse_buffer(reserve, RESERVE_BUFFER_SIZE(tokens_per_set), argv[2]);
	parse_buffer(keys, SEALED_KEYS_SIZE, argv[3]);
	parse_buffer(&pk, sizeof(pub_key_s), argv[4]);

	sgx_enclave_id_t enclave_id;
	sgx_status_t result;
	enclave_error_t error;
	result = sgx_create_enclave(ENCLAVE, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);
	if (result != SGX_SUCCESS) fail("Failed to Launch Enclave");
	result = reencrypt(enclave_id, &error, pk, index, tokens_per_set, RESERVE_BUFFER_SIZE(tokens_per_set), RESULT_BUFFER_SIZE(tokens_per_set), SEALED_KEYS_SIZE, keys, reserve, result_buffer);
	if (result != SGX_SUCCESS) fail("Failed to Run Enclave");
	switch (error) {
		case ENCLAVE_NO_ERROR:			break;
		case ENCLAVE_ARGUMENT_ERROR:	fail("Invalid Arguments");
		case ENCLAVE_OOM_ERROR:			fail("EPC Memory Full");
		case ENCLAVE_SDK_ERROR:			fail("SGX SDK Error");
		case ENCLAVE_CRYPTO_ERROR:		fail("Cryptography Failed");
		case ENCLAVE_ORAM_ERROR:		fail("Failed to Hide Memory Access Pattern");
		default:						fail("Unexpected Error");
	}
	puts("OK");
	printbuf(result_buffer, RESULT_BUFFER_SIZE(tokens_per_set));
}

void update_cmd(int argc, char* argv[]) {
	if (argc != 3) fail_usage();

	size_t pib_len = strlen(argv[2]);
	if (pib_len != 210) fail_usage();
	pib_len /= 2;
	uint8_t* pib = malloc(pib_len);
	if (!pib) fail("Out of Memory");
	sodium_hex2bin(pib, pib_len, argv[2], pib_len * 2, NULL, NULL, NULL);
	if (pib[0] != 21) fail("Unsupported PIB Type");
	if (pib[1] != 1 && pib[1] != 2) fail("Unsupported PIB Version");
	if (pib[2] != 0) fail("Invalid PIB Length");
	if (pib[3] != 101) fail("Invalid PIB Length");
	sgx_update_info_bit_t info;
	sgx_platform_info_t* ptr = (sgx_platform_info_t*)(pib + 4);
	switch (sgx_report_attestation_status(ptr, 1, &info)) {
		case SGX_SUCCESS:
			puts("OK");
			puts("TCB up to Date");
			break;
		case SGX_ERROR_AE_INVALID_EPIDBLOB:
			puts("ERROR");
			puts("EPID Blob Corrupted");
			break;
		case SGX_ERROR_UPDATE_NEEDED:
			puts("OK");
			puts("Update Needed for:");
			if (info.ucodeUpdate) puts("- Microcode");
			if (info.csmeFwUpdate) puts("- CSME Firmware");
			if (info.pswUpdate) puts("- Platform Software");
			break;
		case SGX_ERROR_OUT_OF_MEMORY:
			puts("ERROR");
			puts("Out of Memory");
			break;
		case SGX_ERROR_SERVICE_UNAVAILABLE:
			puts("ERROR");
			puts("AE Service Unresponsive");
			break;
		case SGX_ERROR_SERVICE_TIMEOUT:
			puts("ERROR");
			puts("AE Service Timed Out");
			break;
		case SGX_ERROR_BUSY:
			puts("ERROR");
			puts("Service Unavailable. Try Again.");
			break;
		case SGX_ERROR_NETWORK_FAILURE:
			puts("ERROR");
			puts("Network Unavalable.");
			break;
		case SGX_ERROR_OUT_OF_EPC:
			puts("ERROR");
			puts("Out of EPC Memory");
			break;
		case SGX_ERROR_UNRECOGNIZED_PLATFORM:
			puts("ERROR");
			puts("EPID Unknown");
			break;
		default:
			puts("ERROR");
			puts("Unexpected Error");
			break;
	}
	free(pib);
}

void help_cmd(int argc, char* argv[]) {
	if (argc != 2) fail_usage();

	puts("OK");
	printf("Usage: %s command [parameter1 [parameter2 [...]]]\n", argv[0]);
	puts("The following commands are supported:");
	puts("    generate");
	puts("    reencrypt");
	puts("    update");
	puts("    help");
	puts("    version");
	puts("");
	puts("generate");
	printf("Usage:          %s generate public-keys-count reserve-count\n", argv[0]);
	puts("                   oversize-factor output-type tokens-per-set");
	puts("Description:    Generates and encrypts tokens.");
	puts("Parameters:");
	puts("    public-keys-count:  The number of public keys for which tokens should be");
	puts("                        generated. (<= 1'000'000)");
	puts("    reserve-count:      The number of reserve token sets to be genrated.");
	puts("                        (<= 1'000'000)");
	puts("    oversize-factor:    Asymplotically the number of tokens generated per");
	puts("                        requested token set (<= 1'000, > 0, precision 0.001)");
	puts("    output-type:        Currently either `raw' or `hash', indicating whether or");
	puts("                        not to hash the unencrypted tokens.");
	puts("    tokens-per-set:     The number of tokens contained in each set.");
	puts("                        (<= 1'000, > 0)");
	puts("Input:");
	puts("    public-keys-count lines, each containing one public key for which tokens");
	puts("        should be generated.");
	puts("Result:");
	puts("    public-keys-count lines, each containing one token set encrypted for the");
	puts("        corresponding public key and signed with the enclave's primary signing");
	puts("        key");
	puts("    reserve-count lines, each containing one reserve token set which can be");
	puts("        passed to a `reencrypt' call");
	puts("    one line containing the enclave keys which can be passed to a `reencrypt'");
	puts("        call");
	puts("    one line containing the configurations and public keys attested by the");
	puts("        report (see report below)");
	puts("    one line containing the enclave quote which can be verified by the Intel");
	puts("        Attestation Service");
	puts("    the remaining lines contain one unencrypted token each, encoded as specified");
	puts("        by the output-type parameter");
	puts("");
	puts("reencrypt");
	printf("Usage:          %s reencrypt encrypted-tokens enclave-keys\n", argv[0]);
	puts("                   public-key index");
	puts("                tokens-per-set");
	puts("Description:    Reencrypts reserve tokens for the specified public key");
	puts("Parameters:");
	puts("    encrypted-tokens:   One set of encrypted reserve tokens, as generated by a");
	puts("                        `generate' call.");
	puts("    enclave-keys:       The enclave keys, as generated by the corresponding");
	puts("                        `generate' call.");
	puts("    public-key:         The public key for which the tokens are to be encrypted.");
	puts("    index:              The (0-based) index of the set of reserve tokens ammong");
	puts("                        all reserve token sets generated by the corresponding");
	puts("                        `generate' call.");
	puts("    tokens-per-set:     The number of tokens contained in each set. (> 0)");
	puts("Input:          stdin is ignored");
	puts("Result:         One set of tokens, encrypted for the specified public key and");
	puts("                signed with the seccondary signing key specified.");
	puts("");
	puts("update");
	printf("Usage:          %s update platform-info-blob\n", argv[0]);
	puts("Description:    Processes the platform info blob received from the intel");
	puts("                attestation server.");
	puts("Parameters:");
	puts("    platform-info-blob: The hex ('Base 16') encoded platform info blob as");
	puts("                        obtained from the intel attestation server.");
	puts("Input:          stdin is ignored");
	puts("Result:         Update Status of the Platform Software.");
	puts("");
	puts("help");
	printf("Usage:          %s help\n", argv[0]);
	puts("Description:    Prints this help message. Parameters are ignored.");
	puts("Parameters:     None");
	puts("Input:          stdin is ignored");
	puts("Result:         This help message");
	puts("");
	puts("version");
	printf("Usage:          %s version\n", argv[0]);
	puts("Description:    Prints the version of this tool as well as the linked libraries.");
	puts("Parameters:     None");
	puts("Input:          stdin is ignored");
	puts("Result:         Version information");
	puts("");
	puts("Notes:");
	puts("All binary data should be base64 encoded before being passed as parameters or");
	puts("    stdin.");
	puts("All numbers should be passed in decimal form. If they are negative or larger");
	printf("    than allowed, the behavior of `%s' is undefined.\n", argv[0]);
	puts("All outputed binary data is base64 encoded.");
	printf("The first ouput line of `%s' is always `OK' or `ERROR', indicating\n", argv[0]);
	puts("    whether the call has succeeded. Note that neither of these is valid base64.");
	puts("");
	puts("Report:");
	puts("The report data attested to by the SGX quote contains the following:");
	puts("4 bytes     version number of the report, little endian");
	puts("4 bytes     number of reserve key sets generated, little endian");
	puts("4 bytes     number of key sets generated for specific public keys, little endian");
	puts("4 bytes     number of tokens per token set, little endian");
	puts("4 bytes     numerator of the oversize factor");
	puts("4 bytes     denominator of the oversize factor");
	puts("32 bytes    primary public key. Can be used to verify signature for non-reserve");
	puts("            key sets");
	puts("32 bytes    seccondary public key. Can be used to verify signature for reserve");
	puts("            key sets");
}

void version_cmd(int argc, char* argv[]) {
	UNUSED(argv);
	if (argc != 2) fail_usage();

	puts("OK");
	puts("Component               Version");
	puts("zkacli                  1.0.1 (" GIT_COMMIT ")");
	puts("libsodium               'stable' Branch (" SODIUM_COMMIT ")");
	puts("Enclave                 " SGX_ENCLAVE_HASH);
	puts("SGX SDK                 " SDK_VERSION);
	puts("Compiler                " COMPILER_VERSION);
	puts("Build Date              " BUILD_DATE);
	puts("Unsigned Enclave        " ENCLAVE_UNSIGNED_SHA256);
	puts("Signed Enclave          " ENCLAVE_SIGNED_SHA256);
	puts("enclave.signdata.sig    " SIGNDATA_SIG_BASE64);
	puts("enclave.signdata        " SIGNDATA_BASE64);
	puts("sign.pem                " SIGN_PEM_BASE64);
}

int main(int argc, char* argv[]) {
	SIZE_CHECKS();
	name = argv[0];
	if (argc < 2) fail_usage();
	else if (!strcmp(argv[1], "generate")) generate_cmd(argc, argv);
	else if (!strcmp(argv[1], "reencrypt")) reencrypt_cmd(argc, argv);
	else if (!strcmp(argv[1], "update")) update_cmd(argc, argv);
	else if (!strcmp(argv[1], "help")) help_cmd(argc, argv);
	else if (!strcmp(argv[1], "version")) version_cmd(argc, argv);
	else fail_usage();
}
