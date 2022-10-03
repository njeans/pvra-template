#!/bin/bash
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#


if [[ -z "${CCF_ENABLE}" ]]; 
then
  echo "Error: environment variable CCF_ENABLE not set."
  exit
fi


if [[ -z "${SGX_SPID}" ]]; 
then
  echo "Error: environment variable SGX_SPID not set."
  exit
fi

if [[ -z "${IAS_PRIMARY_KEY}" ]]; 
then
  echo "Error: environment variable IAS_PRIMARY_KEY not set."
  exit
fi


test -d test_sgx || mkdir test_sgx
cd ./test_sgx
rm -rf *
rm -rf ./client/
rm -rf ./host/




### 0.0 INITIALIZE FRAMEWORK COMPONENTS ###

### 0.1 SCS INIT: Request Freshness Tag for newly initialized PVRA-enclave (sets FT = 256b'00...00') ###

if [ ! ${CCF_ENABLE} ];
then 
  cp ../service_cert.pem .
  cp ../user0_cert.pem .
  cp ../user0_privk.pem .
  echo -n "[biPVRA] INITSCS Freshness Tag: "
  curl -s https://127.0.0.1:8000/app/scs/request -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "4", "init": "0000000000000000000000000000000000000000000000000000000000000000"}' > init.txt

  if [[ $(grep init.txt -e "true") ]] 
  then
    echo "success"
  else
    echo "Error: CCF NOT RUNNING LOCALLY."
    exit
  fi
fi


### 0.2 BulletinBoard INIT: [TODO][BULLETIN]: Setup Bulletin Board for this enclave ###






### 1.0 INITIALIZE PVRA ENCLAVE ###

### 1.1 initPVRA: Generates all enclave keys, initializes enclave state, and generates quote ###

echo "[biPVRA] Launch initPVRA from bash script."
../app/app --initPVRA --enclave-path `pwd`/../enclave/enclave.signed.so \
  --sealedState sealedState.bin \
  --quotefile quote.bin \
  --signature enckey.sig

cp sealedState.bin sealedState0.bin
  

### 1.2 Runs Auditee as well as extracts enclave public secp256r1 signing key to signingkey.pem ###

echo ""
echo "[biPVRA] Running Auditee to Extract PVRA signing_key"

source ~/.venvs/auditee/bin/activate
python3.7 ../auditee_extract.py

# [TODO][BULLETIN]: ias_report.json posted to Bulletin Board




### 2.0 PREPARE TO RUN PVRA APPLICATION ###

### 2.1 Verify signed enclave encryption key using signingkey.pem (extracted enclave signing key) ###

echo -n "[biPVRA] Verifying signed enclave_enc_key using extracted enclave_sign_key: "
openssl dgst -sha256 -verify signingkey.pem -signature enckey.sig enckey.dat

### 2.2 SETUP CLIENT ENVIRONMENT ###
mkdir client 
cp ../client.sh ./client
cp ../pvraClientCommand.sh ./client
cp ./enckey.dat ./client
cp ../encrypt_command ./client
cp ../format_command ./client


### 2.3 SETUP HOST ENVIRONMENT ###
mkdir host
cp ../host.sh ./host
cp ../pvraHostCommand.sh ./host

if [ ! ${CCF_ENABLE} ];
then
  cp ../service_cert.pem ./host
  cp ../user0_cert.pem ./host
  cp ../user0_privk.pem ./host
fi
cp ./sealedState0.bin ./host

exit 


