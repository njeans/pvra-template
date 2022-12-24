#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

include common/common.mk

.PHONY: all clean untrusted enclave

all:
	$(MAKE) $(MFLAGS) -C enclave SGX_MODE=$(SGX_MODE) $(MAKECMDGOALS)
	$(MAKE) $(MFLAGS) -C untrusted SGX_MODE=$(SGX_MODE) $(MAKECMDGOALS)

enclave:
	$(MAKE) $(MFLAGS) -C enclave SGX_MODE=$(SGX_MODE)


untrusted:
	$(MAKE) $(MFLAGS) -C untrusted SGX_MODE=$(SGX_MODE)

clean:
	$(MAKE) $(MFLAGS) -C enclave SGX_MODE=$(SGX_MODE) $(MAKECMDGOALS)
	$(MAKE) $(MFLAGS) -C untrusted SGX_MODE=$(SGX_MODE) $(MAKECMDGOALS)
	rm -rf bin
