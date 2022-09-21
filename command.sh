#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#




printf "[bcPVRA] Host<-Client eAESkey+eCMD\n"
printf "[bcPVRA] Host->SCS updateFT(...)\n"
#gen FT = Hash(FTold || Hash(sealedstate || eCMD))
#curl https://127.0.0.1:8000/app/scs/update -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "4", "commit": "a547891be9ed742869b0cdac2644c0ba676ec14da845fb8ab072eea7bc221ca0"}'
printf "[bcPVRA] Host<-SCS signedFT = fc857532b55796a46aace6a53c3392763b7be4a43f05526888da5a57438b120e\n"
#sample CCF signature for debug
# TODO: call CCF with Hash(sealedstate || eCMD), parse resopnse for signedFT.bin and FT.bin
cp /home/azureuser/mbehnia/pvra-template/scratch/signedFT.bin .
echo -n "hello" > FT.txt


#printf "[bcPVRA] Invoking commandPVRA\n"
../app/app --commandPVRA --enclave-path `pwd`/../enclave/enclave.signed.so \
  --sealedState sealedState.bin \
  --signedFT signedFT.bin \
  --FT FT.txt \
  --eCMD eCMD.bin \
  --eAESkey eAESkey.bin \
  --cResponse cResponse.txt \
  --cRsig cResponse.sig \
  --sealedOut sealedOut.bin


echo "[bcPVRA] Host->Client cResponse"





mv sealedOut.bin sealedState.bin

