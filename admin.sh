#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#


test -d test_sgx || mkdir test_sgx
cd ./test_sgx
rm -f *


### 0.0 INITIALIZE FRAMEWORK COMPONENTS ###

### SCS INIT ###

#../tests/sandbox/sandbox.sh --enclave-type virtual -p ./samples/apps/counter/libcounter.virtual.so
cp /home/azureuser/mbehnia/ccf-2.0.1/build/workspace/sandbox_common/service_cert.pem .
cp /home/azureuser/mbehnia/ccf-2.0.1/build/workspace/sandbox_common/user0_cert.pem .
cp /home/azureuser/mbehnia/ccf-2.0.1/build/workspace/sandbox_common/user0_privk.pem .

curl https://127.0.0.1:8000/app/scs/request -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "18", "init": "0000000000000000000000000000000000000000000000000000000000000000"}'



### BulletinBoard INIT ###


#curl https://127.0.0.1:8000/app/scs/read -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "4", "nonce": "test"}' | grep -ioE 'signature":".*","value' | cut -d "\"" -f3  > test.txt

#curl https://127.0.0.1:8000/app/scs/update -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "4", "commit": "a547891be9ed742869b0cdac2644c0ba676ec14da845fb8ab072eea7bc221ca0"}' | grep -ioE 'signature":".*","value' | cut -d "\"" -f3  > test.txt


### 1.0 INITIALIZE PVRA ENCLAVE ###

printf "\n[biPVRA] INITPVRA LAUNCH\n"
../app/app --initPVRA --enclave-path `pwd`/../enclave/enclave.signed.so \
  --sealedState sealedState.bin \
  --quotefile quote.bin \
  --signature enckey.sig
  
echo "\n[biPVRA] Running Auditee to Extract PVRA_signing_key\n"

#source ~/.venvs/auditee/bin/activate
python3.7 ../auditee_extract.py
# TODO: get auditee to pull current project 
#ias_report.json ready to be posted to BulletinBoard




### 2.0 RUNNING PVRA APPLICATION ###

openssl dgst -sha256 -verify signingkey.pem -signature enckey.sig enckey.dat



#pre-generated AES key for debug
cp /home/azureuser/mbehnia/pvra-template/scratch/aes128gcm.pem .
# one-time
openssl rsautl -encrypt -pubin -inkey enckey.dat -in aes128gcm.pem > eAESkey.bin
cp /home/azureuser/mbehnia/pvra-template/debug/aes/encrypt_command .


# OLD
#cType uid test_result seqNo client_id
#echo -en '\xde\xad\xbe\xef' > CMD.bin
#./encrypt_command {1,{0},0,0} > /dev/null
#cp /home/azureuser/mbehnia/pvra-template/scratch/eCMD.bin .


echo "\n"


cd ..
./light.sh

