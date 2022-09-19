#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

cd ./test_sgx


### ONLY RUNNING A COMMAND ###


printf "[bcPVRA] Client generating AES session key\n"
#pre-generated AES key for debug
cp /home/azureuser/mbehnia/pvra-template/scratch/aes128gcm.pem .

printf "[bcPVRA] Client encrypting AES session key\n"
openssl rsautl -encrypt -pubin -inkey enckey.dat -in aes128gcm.pem > eAESkey.bin
cp /home/azureuser/mbehnia/pvra-template/debug/aes/encrypt_command .
printf "[bcPVRA] Client encrypting command\n"
./encrypt_command {1,{0},0,0} > /dev/null
#cp /home/azureuser/mbehnia/pvra-template/scratch/eCMD.bin .



printf "[bcPVRA] Client->Host eCMD+eAESkey sent\n"




printf "[bcPVRA] Host requesting new signedFT\n"
#gen FT = Hash(FTold || Hash(sealedstate || eCMD))

cat sealedState.bin eCMD.bin > se.bin
openssl dgst -r -sha256 se.bin | head -c 64 > se.hash
#echo "[bcPVRA] Host Computed sealcmd"
#cat se.hash
echo -n "0000000000000000000000000000000000000000000000000000000000000000" > ftold.hash
cat ftold.hash se.hash > ft.bin
openssl dgst -r -sha256 ft.bin | head -c 64 > ft.hash
echo -n "\n[bcPVRA] Host Computed newFT: "
cat ft.hash

#curl https://127.0.0.1:8000/app/scs/update -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "4", "commit": "a547891be9ed742869b0cdac2644c0ba676ec14da845fb8ab072eea7bc221ca0"}'
#sample CCF signature for debug

cp /home/azureuser/mbehnia/pvra-template/scratch/signedFT.bin .



printf "\n[bcPVRA] Host COMMANDPVRA LAUNCH\n"
../app/app --commandPVRA --enclave-path `pwd`/../enclave/enclave.signed.so \
  --sealedState sealedState.bin \
  --signedFT signedFT.bin \
  --eCMD eCMD.bin \
  --eAESkey eAESkey.bin \
  --cResponse cResponse.txt \
  --cRsig cResponse.sig \
  --sealedOut sealedOut.bin


printf "[bcPVRA] Host->Client cResponse sent\n"
#python3.7 ../extract_verify.py
openssl dgst -sha256 -verify signingkey.pem -signature cResponse.sig cResponse.txt
