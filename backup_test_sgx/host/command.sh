#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#




printf "[bcPVRA] Host<-Client eAESkey+eCMD\n"


printf "[bcPVRA] Host->SCS updateFT(...)\n"

cat sealedState.bin eCMD.bin > se.bin 
openssl dgst -r -sha256 se.bin | head -c 64 > se.hash
value=`cat se.hash`
final="{\"id\": \"28\", \"commit\": \"${value}\"}"

curl -s https://127.0.0.1:8000/app/scs/update -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary "$final" > scsupdate.txt




cat scsupdate.txt | grep -ioE 'signature":".*}' | cut -d "\"" -f3 | sed 's/\\n/\n/g'  > signedFT.txt
cat scsupdate.txt | grep -ioE 'signature":".*}' | cut -d "\"" -f7  > FT.txt
base64 -d signedFT.txt > signedFT.bin


printf "[bcPVRA] Host<-SCS signedFT = "
cat FT.txt


../app/app --commandPVRA --enclave-path `pwd`/../enclave/enclave.signed.so \
  --sealedState sealedState.bin \
  --signedFT signedFT.bin \
  --FT FT.txt \
  --eCMD eCMD.bin \
  --eAESkey eAESkey.bin \
  --cResponse cResponse.txt \
  --cRsig cResponse.sig \
  --sealedOut sealedOut.bin






