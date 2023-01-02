#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

include ../common/common.mk
include ../common/rules.mk

Enclave_Include_Paths := -I$(SGX_SDK)/include \
       -I$(SGX_SDK)/include/tlibc \
       -I../trustedLib/secp256k1/include \
       -I$(SGXSSL_PKG_PATH)/include \
       -I../interface #\
	   -I$(SGX_SDK)/SampleCode/SampleAttestedTLS/sgx_socket/include \

SGX_EDGER8R_FLAGS += --trusted-dir ../interface \
	--search-path $(SGXSSL_PKG_PATH)/include  #\
    --search-path $(SGX_SDK)/SampleCode/SampleAttestedTLS/sgx_socket/include

CFLAGS += $(Enclave_Include_Paths) $(SGX_ENCLAVE_CFLAGS) -std=c99 -Wno-unused-parameter
CXXFLAGS += $(SGX_ENCLAVE_CXXFLAGS)
CPPFLAGS += $(Enclave_Include_Paths) $(SGX_ENCLAVE_CPPFLAGS)
LDFLAGS += -L../trustedLib/secp256k1/lib $(SGX_ENCLAVE_LDFLAGS) -L$(SGXSSL_PKG_PATH)/lib64
LDLIBS += -lenclave_stub_t -lsecp256k1 $(SGX_ENCLAVE_LDLIBS)

CFLAGS+=-w
CFLAGS+=-fcompare-debug-second

.PHONY: all clean

all: ../interface/libenclave_stub_t.a enclave.signed.so
	@mkdir -p ../bin
	@mv enclave.signed.so  enclave.unsigned.so enclave.key.pem ../bin
	@mv *.o ../bin

../interface/libenclave_stub_t.a: ../interface/enclave.edl

enclave.unsigned.so: getaddrinfo.o htonl.o htons.o ../trustedLib/secp256k1/lib/libsecp256k1.a print.o enclave_state.o initPVRA.o commandPVRA.o appPVRA.o auditlogPVRA.o keccak256.o util.o merkletree.o
#decode_sgx_status.o  trusted_sgx_socket.o

enclave.signed.so: enclave.key.pem

enclave.key.pem:
	openssl genrsa -3 -out $@ 3072

clean:
	rm -f ../interface/*_t.* enclave.key.pem enclave.unsigned.so enclave.signed.so *.o ../bin/enclave.unsigned.so  ../bin/enclave.signed.so  ../bin/*.o