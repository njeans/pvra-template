#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

include common/common.mk

.PHONY: all clean

all: enclave.signed.so untrusted

enclave.signed.so:
	$(MAKE) $(MFLAGS) -C enclave SGX_MODE=$(SGX_MODE)


untrusted:
	$(MAKE) $(MFLAGS) -C app SGX_MODE=$(SGX_MODE)


clean:
	$(MAKE) $(MFLAGS) -C enclave SGX_MODE=$(SGX_MODE) $(MAKECMDGOALS)
	$(MAKE) $(MFLAGS) -C app SGX_MODE=$(SGX_MODE) $(MAKECMDGOALS)
	rm -rf bin
