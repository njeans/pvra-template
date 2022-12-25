######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGXSSL_SDK ?= /opt/intel/sgxssl
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 0


ifeq ($(shell getconf LONG_BIT), 32)
    SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
    SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
    SGX_COMMON_FLAGS := -m32
    SGX_LIBRARY_PATH := $(SGX_SDK)/lib
else
    SGX_COMMON_FLAGS := -m64
    SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
endif

SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/$(SGX_ARCH)/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/$(SGX_ARCH)/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_FLAGS += -O0 -g
else
    SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_FLAGS += -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fstack-protector-all
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := -Wnon-virtual-dtor -std=c++11


SGXSSL_PKG_PATH := $(SGXSSL_SDK)/Linux/package


ifeq ($(SGX_MODE), HW)
    SGX_SIM_LIB :=
else
	# Add to library name if running in simulator mode
    SGX_SIM_LIB := _sim
endif

### SGX libraries i.e. LDLIBS = -L$(SGX_LIBRARY_PATH) -l$(SGX_thing_LIB)

SGX_URTS_LIB := sgx_urts$(SGX_SIM_LIB)
SGX_UAE_SERVICE_LIB := sgx_uae_service$(SGX_SIM_LIB)
SGX_TRTS_LIB := sgx_trts$(SGX_SIM_LIB)
SGX_TSERVICE_LIB := sgx_tservice$(SGX_SIM_LIB)

SGXSSL_U_Library_Name := sgx_usgxssl
SGXSSL_Library_Name := sgx_tsgxssl
OpenSSL_SSL_Library_Name := sgx_tsgxssl_ssl
OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
U_TLS_Library_Name := sgx_utls
SGX_TLS_Library_Name := sgx_ttls

### BEGIN Host (untrusted) application settings ###

SGX_HOST_CFLAGS := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -D_GNU_SOURCE
SGX_HOST_CXXFLAGS := $(SGX_COMMON_CXXFLAGS)
SGX_HOST_CPPFLAGS := -I$(SGX_SDK)/include
SGX_HOST_LDFLAGS := -L$(SGXSSL_PKG_PATH)/lib64
SGX_HOST_LDLIBS := -L$(SGX_LIBRARY_PATH) -l$(SGX_URTS_LIB) -l$(SGX_UAE_SERVICE_LIB) -lpthread  -l$(SGXSSL_U_Library_Name) -l$(U_TLS_Library_Name)
# SGX_HOST_LDLIBS := -L$(SGX_LIBRARY_PATH) -l$(SGX_URTS_LIB) -l$(SGX_UAE_SERVICE_LIB) -lpthread

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
    SGX_HOST_CPPFLAGS += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
    SGX_HOST_CPPFLAGS += -DNDEBUG -DEDEBUG -UDEBUG
else
    SGX_HOST_CPPFLAGS += -DNDEBUG -UEDEBUG -UDEBUG
endif

### END Host (untrusted) application settings ###

### BEGIN Enclave (trusted app) settings ###

SGX_ENCLAVE_CFLAGS := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fno-builtin

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
    SGX_ENCLAVE_CFLAGS += -fstack-protector
else
    SGX_ENCLAVE_CFLAGS += -fstack-protector-strong
endif

SGX_ENCLAVE_CXXFLAGS := $(SGX_COMMON_CXXFLAGS) -nostdinc++
SGX_ENCLAVE_CPPFLAGS := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/SampleCode/SampleAttestedTLS/sgx_socket/include -I$(SGXSSL_PKG_PATH)/include
SGX_ENCLAVE_LDFLAGS := \
    -nostdlib \
	-nodefaultlibs \
	-nostartfiles \
	-Wl,-Bstatic \
	-Wl,-Bsymbolic \
	-Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry \
	-Wl,--export-dynamic \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=enclave.lds

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.

SGX_ENCLAVE_LDLIBS := -L$(SGX_LIBRARY_PATH) -L$(SGXSSL_PKG_PATH)/lib64 \
	-Wl,--whole-archive -l$(SGX_TRTS_LIB) -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \
	 -l$(OpenSSL_Crypto_Library_Name) \
	-Wl,--start-group  -lsgx_pthread -lmbedtls_SGX_t -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l$(SGX_TSERVICE_LIB) -l$(SGX_TLS_Library_Name) -Wl,--end-group
 

### END Enclave (trusted app) settings ###
