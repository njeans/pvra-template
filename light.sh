#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#


cd ./test_sgx



# FOR DEBUG: if need to reset from application state0
curl https://127.0.0.1:8000/app/scs/request -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "28", "init": "0000000000000000000000000000000000000000000000000000000000000000"}'
cp sealedState0.bin sealedState.bin
state_counter=0




echo "[client] Generating and encrypting AES session key"
openssl rand -hex 16 | xxd -r -p > sessionAESkey.bin
openssl rsautl -encrypt -pubin -inkey enckey.dat -in sessionAESkey.bin > eAESkey.bin
echo "[client] Encrypting Command 0 0 0 0 0"
./encrypt_command 0 0 0 0 0 sessionAESkey.bin > /dev/null
echo "[client] Client->Host eCMD\n"
../command.sh
state_counter=$((state_counter+1))
filename="sealedState${state_counter}.bin" 
cp sealedOut.bin $filename
mv sealedOut.bin sealedState.bin
echo "[bcPVRA] Host->Client cResponse"



echo -n "\n[client] Verifying cResponse signature: "
openssl dgst -sha256 -verify signingkey.pem -signature cResponse.sig cResponse.txt




echo "[client] Generating and encrypting AES session key"
openssl rand -hex 16 | xxd -r -p > sessionAESkey.bin
openssl rsautl -encrypt -pubin -inkey enckey.dat -in sessionAESkey.bin > eAESkey.bin
echo "[client] Encrypting Command 0 0 0 0 0"
./encrypt_command 1 0 0 1 0 sessionAESkey.bin > /dev/null
echo "[client] Client->Host eCMD\n"
../command.sh
state_counter=$((state_counter+1))
filename="sealedState${state_counter}.bin" 
cp sealedOut.bin $filename
mv sealedOut.bin sealedState.bin
echo "[bcPVRA] Host->Client cResponse"



echo -n "\n[client] Verifying cResponse signature: "
openssl dgst -sha256 -verify signingkey.pem -signature cResponse.sig cResponse.txt





echo "[client] Generating and encrypting AES session key"
openssl rand -hex 16 | xxd -r -p > sessionAESkey.bin
openssl rsautl -encrypt -pubin -inkey enckey.dat -in sessionAESkey.bin > eAESkey.bin
echo "[client] Encrypting Command 0 0 0 0 0"
./encrypt_command 0 0 0 2 0 sessionAESkey.bin > /dev/null
echo "[client] Client->Host eCMD\n"
../command.sh
state_counter=$((state_counter+1))
filename="sealedState${state_counter}.bin" 
cp sealedOut.bin $filename
mv sealedOut.bin sealedState.bin
echo "[bcPVRA] Host->Client cResponse"



echo -n "\n[client] Verifying cResponse signature: "
openssl dgst -sha256 -verify signingkey.pem -signature cResponse.sig cResponse.txt



echo "[client] Generating and encrypting AES session key"
openssl rand -hex 16 | xxd -r -p > sessionAESkey.bin
openssl rsautl -encrypt -pubin -inkey enckey.dat -in sessionAESkey.bin > eAESkey.bin
echo "[client] Encrypting Command 0 0 0 0 0"
./encrypt_command 1 0 0 3 0 sessionAESkey.bin > /dev/null
echo "[client] Client->Host eCMD\n"
../command.sh
state_counter=$((state_counter+1))
filename="sealedState${state_counter}.bin" 
cp sealedOut.bin $filename
mv sealedOut.bin sealedState.bin
echo "[bcPVRA] Host->Client cResponse"



echo -n "\n[client] Verifying cResponse signature: "
openssl dgst -sha256 -verify signingkey.pem -signature cResponse.sig cResponse.txt