#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

include ../common/common.mk
include ../common/rules.mk

Enclave_Include_Paths := -L ../trustedLib/mbedtls_SGX-2.6.0/ -L ../trustedLib/secp256k1/

SGX_EDGER8R_FLAGS += --trusted-dir ../interface
CFLAGS += $(SGX_ENCLAVE_CFLAGS) -std=c99 -Wno-unused-parameter
CXXFLAGS += $(SGX_ENCLAVE_CXXFLAGS)
CPPFLAGS += -I ../trustedLib/mbedtls_SGX-2.6.0/include -I ../trustedLib/secp256k1/include $(SGX_ENCLAVE_CPPFLAGS) -I../interface
LDFLAGS += -L ../trustedLib/mbedtls_SGX-2.6.0/lib -lmbedtls_sgx_t -L ../trustedLib/secp256k1/lib -lsecp256k1 $(SGX_ENCLAVE_LDFLAGS)
LDLIBS += -L ../interface -lenclave_stub_t -lsecp256k1 $(SGX_ENCLAVE_LDLIBS) 


CFLAGS+=-w
CFLAGS+=-fcompare-debug-second

.PHONY: all clean

all: ../interface/libenclave_stub_t.a enclave.signed.so
	@mkdir -p ../bin
	@mv enclave.signed.so  enclave.unsigned.so enclave.key.pem ../bin
	@mv *.o ../bin

../interface/libenclave_stub_t.a: ../trustedLib/mbedtls_SGX-2.6.0/lib/mbedtls_SGX.edl ../interface/enclave.edl

enclave.unsigned.so: ../trustedLib/secp256k1/lib/libsecp256k1.a ../trustedLib/mbedtls_SGX-2.6.0/lib/libmbedtls_sgx_t.a  calcbuffsize.o print.o enclave_state.o initPVRA.o commandPVRA.o appPVRA.o auditlogPVRA.o keccak256.o util.o merkletree.o

enclave.signed.so: enclave.key.pem

enclave.key.pem:
	openssl genrsa -3 -out $@ 3072

clean:
	rm -f ../interface/*_t.* enclave.key.pem enclave.unsigned.so enclave.signed.so *.o ../bin/enclave.unsigned.so  ../bin/enclave.signed.so  ../bin/*.o
