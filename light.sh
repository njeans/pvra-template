#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

cd ./test_sgx

./encrypt_command 0 0 1 0 0 > /dev/null
../command.sh

./encrypt_command 0 0 1 0 0 > /dev/null
../command.sh

./encrypt_command 0 0 0 0 0 > /dev/null
../command.sh

./encrypt_command 0 0 0 0 0 > /dev/null
../command.sh


./encrypt_command 1 0 1 0 0 > /dev/null
../command.sh