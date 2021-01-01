SODIUM_COMMIT := bfcfa87f2d211bc072a56b203015122f7678bf04

MITIGATION-CVE-2020-0551 := LOAD

include $(SGX_SDK)/buildenv.mk

SDK := $(SGX_SDK)
SODIUM_PATH ?= $(CURDIR)/libsodium
MODE ?= PRERELEASE

LIB := $(SDK)/lib64
SIG := $(SDK)/bin/x64/sgx_sign
EDGER := $(SDK)/bin/x64/sgx_edger8r
INC := $(SDK)/include

FLAGS := -m64 -Wall -Wextra -mavx2 -Og -gdwarf-4 -I$(CURDIR)/enclave -I$(SODIUM_PATH)/src/libsodium/include -I$(INC) -D_FORTIFY_SOURCE=2 -fdebug-prefix-map=$(CURDIR)=

APP_FILES := wrapper/wrapper.c
ifeq ($(MODE), DEBUG)
	FLAGS += -UNDEBUG -UEDEBUG -DDEBUG
else ifeq ($(MODE), SIM)
	FLAGS += -UNDEBUG -UEDEBUG -DDEBUG
else ifeq ($(MODE), PRERELEASE)
	FLAGS += -DNDEBUG -DEDEBUG -UDEBUG
else ifeq ($(MODE), RELEASE1)
	FLAGS += -DNDEBUG -UEDEBUG -UDEBUG
else ifeq ($(MODE), RELEASE2)
	FLAGS += -DNDEBUG -UEDEBUG -UDEBUG
else
	FLAGS += $(error unusported build mode $(MODE))
endif
APP_FLAGS := $(FLAGS)

ifeq ($(MODE), SIM)
APP_LFLAGS := -L$(LIB) -lsgx_urts_sim -lsgx_epid_sim
else
APP_LFLAGS := -lsgx_urts -lsgx_epid
endif

APP_LFLAGS +=  -Wl,-rpath=$(CURDIR)
APP_OBJ := $(APP_FILES:.c=.o) crypto/libsodium.a
APP := zkacli

ifeq ($(MODE), SIM)
TRTS_LIB := sgx_trts_sim
SERVICE_LIB := sgx_tservice_sim
else
TRTS_LIB := sgx_trts
SERVICE_LIB := sgx_tservice
endif

ENC_FILES := enclave/enclave.c enclave/crypto/crypto.c enclave/oram/oram.c enclave/oram/linear_oram.c enclave/oram/linear_oram_optimized.s
ENC_FLAGS := $(FLAGS) -I$(INC)/tlibc -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong $(MITIGATION_CFLAGS)
ENC_LFLAGS :=	-Wl,-z,relro,-z,now,-z,noexecstack \
				-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) -L$(LIB) \
				-Wl,--whole-archive -l$(TRTS_LIB) -Wl,--no-whole-archive \
				-Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -l$(SERVICE_LIB) -Wl,--end-group \
				-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
				-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
				-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
				-Wl,--version-script=enclave/enclave.lds

ENC_OBJ := $(ENC_FILES:.c=.o)
ENC_OBJ := $(ENC_OBJ:.s=.o) crypto/libsodium_enclave.a
ENC := enclave.so
ENC_SYMBOLS := enclave.so.debug
ENC_SIG := enclave.signed.so
ENC_SIG_DATA := enclave.signdata
ENC_CONF := enclave/enclave.config.xml
ENC_SIGNATURE := enclave.signdata.sig
SIG_KEY := sign.pem

ifeq ($(MODE), RELEASE1)
CONFIG_MODE := RELEASE
else ifeq ($(MODE), RELEASE2)
CONFIG_MODE := RELEASE
else
CONFIG_MODE := $(MODE)
endif

.PHONY: all run target prerelease release-1 release-2 debug sim
all: .config_$(CONFIG_MODE)
	@$(MAKE) target

release:
	@$(MAKE) MODE=RELEASE1

release-1:
	@$(MAKE) MODE=RELEASE1

release-2:
	@$(MAKE) MODE=RELEASE2

sim:
	@$(MAKE) MODE=SIM

prerelease:
	@$(MAKE) MODE=PRERELEASE

debug:
	@$(MAKE) MODE=DEBUG

ifeq ($(MODE), RELEASE1)
target: $(ENC_SIG_DATA)
else
target: $(APP) $(ENC_SIG)
endif

run: all
	@$(CURDIR)/$(APP) help
	@echo "RN => $(APP) [$(MODE), OK]"

.config_$(CONFIG_MODE):
	@rm -f .config_* $(APP) $(ENC) $(ENC_SYMBOLS) $(ENC_SIG) $(ENC_SIG_DATA) $(ENC_SIGNATURE) $(APP_OBJ) wrapper/enclave_u.* $(ENC_OBJ) enclave/enclave_t.* enclave_dumpfile
	@touch .config_$(CONFIG_MODE)

# enclave_u.h includes the dynamically generated sodium/version.h
wrapper/enclave_u.h: enclave/enclave.edl crypto/libsodium.a
	@cd wrapper && $(EDGER) --untrusted ../enclave/enclave.edl --search-path ../enclave --search-path $(INC)
	@echo "GEN => $@"

wrapper/enclave_u.c: wrapper/enclave_u.h

wrapper/enclave_u.o: wrapper/enclave_u.c
	@$(CC) $(APP_FLAGS) -c $< -o $@
	@echo "CC <= $<"

enclave_dumpfile: $(ENC_SIG)
	@$(SIG) dump -dumpfile enclave_dumpfile -enclave $(ENC_SIG)

wrapper/%.o: wrapper/%.c wrapper/enclave_u.h enclave/enclave.h enclave_dumpfile $(ENC_SIG)
	$(eval SGX_ENCLAVE_HASH=$(shell awk -f get_enclave_hash.awk enclave_dumpfile))
	$(eval BUILD_DATE=$(shell date --iso-8601=seconds -u))
	$(eval GIT_COMMIT=$(shell git rev-parse HEAD))
	$(eval SDK_VERSION=$(shell strings $(ENC_SIG) | awk -f get_sdk_version.awk))
	$(eval COMPILER_VERSION=$(shell $(CC) --version | head -n 1))
	$(eval ENCLAVE_UNSIGNED_SHA256=$(shell sha256sum $(ENC) | cut -d ' ' -f1))
	$(eval ENCLAVE_SIGNED_SHA256=$(shell sha256sum $(ENC_SIG) | cut -d ' ' -f1))
	$(eval SIGNDATA_SIG_BASE64=$(shell base64 -w0 $(ENC_SIGNATURE)))
	$(eval SIGNDATA_BASE64=$(shell base64 -w0 $(ENC_SIG_DATA)))
	$(eval SIGN_PEM_BASE64=$(shell base64 -w0 $(SIG_KEY)))
	@$(CC) $(APP_FLAGS) -DSODIUM_COMMIT='"'$(SODIUM_COMMIT)'"' -DSGX_ENCLAVE_HASH='"'$(SGX_ENCLAVE_HASH)'"' -DBUILD_DATE='"'$(BUILD_DATE)'"' -DGIT_COMMIT='"'$(GIT_COMMIT)'"' -DCOMPILER_VERSION='"'"$(COMPILER_VERSION)"'"' -DSDK_VERSION='"'$(SDK_VERSION)'"' -DENCLAVE_UNSIGNED_SHA256='"'$(ENCLAVE_UNSIGNED_SHA256)'"' -DENCLAVE_SIGNED_SHA256='"'$(ENCLAVE_SIGNED_SHA256)'"' -DSIGNDATA_BASE64='"'$(SIGNDATA_BASE64)'"' -DSIGNDATA_SIG_BASE64='"'$(SIGNDATA_SIG_BASE64)'"' -DSIGN_PEM_BASE64='"'$(SIGN_PEM_BASE64)'"' -c $< -o $@
	@echo "CC <= $<"

$(APP): wrapper/enclave_u.o $(APP_OBJ)
	@$(CC) $^ -o $@ $(APP_LFLAGS)
	@echo "LK => $@"

# enclave_t.h includes the dynamically generated sodium/version.h
enclave/enclave_t.h: enclave/enclave.edl crypto/libsodium_enclave.a
	@cd enclave && $(EDGER) --trusted enclave.edl --search-path . --search-path $(INC)
	@echo "GEN => $@"

enclave/enclave_t.c: enclave/enclave_t.h

$(SODIUM_PATH):
	@git clone https://github.com/jedisct1/libsodium.git $(SODIUM_PATH)

crypto/libsodium.a: $(SODIUM_PATH) crypto/compat.c enclave/enclave.h
	@cd $(SODIUM_PATH) && git clean -xf
	@cd $(SODIUM_PATH) && git checkout ./**
	@cd $(SODIUM_PATH) && git fetch
	@cd $(SODIUM_PATH) && git checkout $(SODIUM_COMMIT)
	@cd $(SODIUM_PATH) && ./configure
	@$(MAKE) clean -C $(SODIUM_PATH)
	@$(MAKE) -C $(SODIUM_PATH)
	@cp $(SODIUM_PATH)/src/libsodium/.libs/libsodium.a crypto
	@echo "GEN => $@"

crypto/libsodium_enclave.a: $(SODIUM_PATH) crypto/Makefile.in crypto/compat.c enclave/enclave.h
	@cd $(SODIUM_PATH) && git clean -xf
	@cd $(SODIUM_PATH) && git checkout ./**
	@cd $(SODIUM_PATH) && git fetch
	@cd $(SODIUM_PATH) && git checkout $(SODIUM_COMMIT)
	@echo "#define HAVE_MEMSET_S\n#undef HAVE_POSIX_MEMALIGN\n#undef HAVE_MMAP\n#undef HAVE_MADVISE\n#undef HAVE_MLOCK" > crypto/utils.c.tmp
	@echo "#include <stdlib.h>\ntypedef size_t rsize_t;\n__attribute__((weak)) extern int memset_s(void* b, rsize_t max, int c, rsize_t n);\n" >> crypto/utils.c.tmp
	@cat $(SODIUM_PATH)/src/libsodium/sodium/utils.c >> crypto/utils.c.tmp
	@mv crypto/utils.c.tmp $(SODIUM_PATH)/src/libsodium/sodium/utils.c
	@cp crypto/Makefile.in $(SODIUM_PATH)/src/libsodium
	@cp crypto/compat.c $(SODIUM_PATH)/src/libsodium
	@cd $(SODIUM_PATH) && ./configure --enable-minimal --without-pthreads
	@$(MAKE) clean -C $(SODIUM_PATH)
	@$(MAKE) -C $(SODIUM_PATH)
	@cp $(SODIUM_PATH)/src/libsodium/.libs/libsodium.a crypto/libsodium_enclave.a
	@echo "GEN => $@"

# Autogenerated code contains harmless allways true if condition
enclave/enclave_t.o: enclave/enclave_t.c
	@$(CC) $(ENC_FLAGS) -Wno-type-limits -c $< -o $@
	@echo "CC <= $<"

enclave/%.o: enclave/%.c enclave/enclave_t.h
	@$(CC) $(ENC_FLAGS) -c $< -o $@
	@echo "CC <= $<"

$(ENC): $(ENC_OBJ) enclave/enclave_t.o
	$(eval GIT_COMMIT=$(shell git rev-parse HEAD))
	@$(CC) $^ -o $@ $(ENC_LFLAGS) -Wl,--build-id=0x$(GIT_COMMIT)
	@echo "LK => $@"
	@objcopy --only-keep-debug $(ENC) $(ENC_SYMBOLS)
	@strip --strip-debug --strip-unneeded $(ENC)
	@echo "ST => $@"

$(ENC_SIG): $(ENC)
ifeq ($(MODE), RELEASE2)
	@$(SIG) catsig -key $(SIG_KEY) -enclave $(ENC) -out $@ -sig $(ENC_SIGNATURE) -unsigned $(ENC_SIG_DATA) -config $(ENC_CONF)
	@echo "SG => $@"
else
	@$(SIG) sign -key enclave/enclave.pem -enclave $(ENC) -out $@ -config $(ENC_CONF)
	@echo "SG => $@"
endif

$(ENC_SIG_DATA): $(ENC)
	@$(SIG) gendata -enclave $(ENC) -out $@ -config $(ENC_CONF)
	@echo "GD => $@"
	@echo "NOTE: complete compilation by:"
	@echo "    1) signing $@ into $(ENC_SIGNATURE)"
	@echo "    2) copying the public key coresponding to the signature to $(SIG_KEY)"
	@echo "    3) running 'make release-2'"

.PHONY: clean

clean:
	@rm -f .config_* $(APP) $(ENC) $(ENC_SYMBOLS) $(ENC_SIG) $(ENC_SIG_DATA) $(ENC_SIGNATURE) $(APP_OBJ) wrapper/enclave_u.* $(ENC_OBJ) enclave/enclave_t.* enclave_dumpfile
	-$(MAKE) clean -C $(SODIUM_PATH)
	@echo clean completed successfully
