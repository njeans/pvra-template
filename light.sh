#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

cd ./test_sgx


echo "[client] Generating and encrypting AES session key"
#cp /home/azureuser/mbehnia/pvra-template/scratch/aes128gcm.pem .
#openssl rsautl -encrypt -pubin -inkey enckey.dat -in aes128gcm.pem > eAESkey.bin
echo "[client] Encrypting Command 0 0 1 0 0"
./encrypt_command 0 0 1 0 0 > /dev/null
echo "[client] Client->Host eCMD\n"
../command.sh
#python3.7 ../extract_verify.py
echo -n "\n[client] Verifying cResponse signature: "
openssl dgst -sha256 -verify signingkey.pem -signature cResponse.sig cResponse.txt


echo "[client] Generating and encrypting AES session key"
#cp /home/azureuser/mbehnia/pvra-template/scratch/aes128gcm.pem .
#openssl rsautl -encrypt -pubin -inkey enckey.dat -in aes128gcm.pem > eAESkey.bin
echo "[client] Encrypting Command 1 0 1 1 0"
./encrypt_command 1 0 1 1 0 > /dev/null
echo "[client] Client->Host eCMD\n"
../command.sh
#python3.7 ../extract_verify.py
echo -n "\n[client] Verifying cResponse signature: "
openssl dgst -sha256 -verify signingkey.pem -signature cResponse.sig cResponse.txt