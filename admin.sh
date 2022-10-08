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


if [[ -z "${NUM_USERS}" ]];
then
  echo "Error: environment variable NUM_USERS not set."
  exit
fi

test -d test_sgx || mkdir test_sgx
cd ./test_sgx
rm -rf *
rm -rf ./client/
rm -rf ./host/




### 0.0 INITIALIZE FRAMEWORK COMPONENTS ###

### 0.1 SCS INIT: Request Freshness Tag for newly initialized PVRA-enclave (sets FT = 256b'00...00') ###

if [[ ${CCF_ENABLE} == "1" ]];
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


### 0.2 BulletinBoard INIT: ... ###
../stop_BB.sh
../run_BB.sh
python3 ../gen_user_keys.py


### 1.0 INITIALIZE PVRA ENCLAVE ###

### 1.1 initPVRA: Generates all enclave keys, initializes enclave state, and generates quote ###

echo "[biPVRA] Launch initPVRA from bash script."
../app/app --initPVRA --enclave-path `pwd`/../enclave/enclave.signed.so \
  --sealedState sealedState.bin \
  --quotefile quote.bin \
  --signature enclave_enc_pubkey.sig \
  --userpubkeys pubkeys.list \
  --sigpubkeys pubkeys.sig

cp sealedState.bin sealedState0.bin
  

### 1.2 Runs Auditee as well as extracts enclave public secp256r1 signing key to signingkey.pem ###

echo ""
echo "[biPVRA] Running Auditee to Extract PVRA signing_key"

source ~/.venvs/auditee/bin/activate
python3.7 ../auditee_extract.py




# [TODO][NERLA]: ias_report.json needs to be posted to Bulletin Board
# Let me know if it needs to be signed by the enclave
# This is returned AFTER initPVRA returns the quote, quote is sent to intel and ias_report.json comes back
# We will have to run ANOTHER ecall to sign it by the enclave
# Alternatively the admin has a key pair, and the admin signs it because the admin is the person with the SPID that requests the ias_report from intel?






### 2.0 PREPARE TO RUN PVRA APPLICATION ###

### 2.1 Verify signed enclave encryption key using signingkey.pem (extracted enclave signing key) ###

echo -n "[biPVRA] Verifying signed encryption key: "
openssl dgst -sha256 -verify signingkey.pem -signature enclave_enc_pubkey.sig enclave_enc_pubkey.bin





### 2.2 Verify signed user pubkeys using signingkey.pem (extracted enclave signing key), the same action carried out by the billboard ###

# The blob enclave signed: hash(64b[user0_pubkey] || 64b[user1_pubkey] || ... || 64b[user4_pubkey])
# This bash code recreates that blob and hash

touch pubkeys_to_be_hashed.bin

line=$(head -n 1 pubkeys.list)
num_keys=$(($line))
iter=2

while [ $num_keys != 0 ]
do
  out=$(awk "FNR>=${iter} && FNR <=${iter}" pubkeys.list | xxd -p -r >> pubkeys_to_be_hashed.bin)
  num_keys=$(($num_keys-1))
  iter=$(($iter+1))
done

echo -n "[biPVRA] Verifying signed userpubkeys: "
openssl dgst -sha256 -verify signingkey.pem -signature pubkeys.sig pubkeys_to_be_hashed.bin




### 2.2 SETUP CLIENT ENVIRONMENT ###
mkdir client 
cp ../client.sh ./client
cp ../pvraClientCommand.sh ./client
cp ./enclave_enc_pubkey.bin ./client
cp ../encrypt_command ./client
cp ../format_command ./client

# [TODO][NERLA]: Copy all generated user key pairs to client environment
# ./client for now will be a SUPER CLIENT that stores all client information
# we can make seperate directories for individual clients potentially later, low priority
cp ./user0_pubkey.bin ./client
cp ./user0_prikey.bin ./client

# [TODO][NERLA]: If you write your ECDH script in client_ecdh.py nothing needs to be done
# Otherwise copy your script to client environment
cp ../client_ecdh.py ./client


### 2.3 SETUP HOST ENVIRONMENT ###
mkdir host
cp ../host.sh ./host
cp ../pvraHostCommand.sh ./host
cp ../pvraAuditCommand.sh ./host
cp ./sealedState0.bin ./host
cp ./signingkey.pem ./host
if [[ ${CCF_ENABLE} == "1" ]];
then
  cp ../service_cert.pem ./host
  cp ../user0_cert.pem ./host
  cp ../user0_privk.pem ./host
fi

exit 


