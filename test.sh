#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

test -d test_sgx || mkdir test_sgx
cd ./test_sgx
#rm -f *
#
printf "\nINIT PVRA Attempt 5,525,910...\n"
../app/app --initPVRA --enclave-path `pwd`/../enclave/enclave.signed.so
