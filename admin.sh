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

# ./run_BB.py ?
# [TODO][NERLA]: I only placed this here temporarily, BulletinBoard init might go after the signed pubkey list (pubkeys.sig) is published by initPVRA, I am not sure


# ./gen_user_keys.py ?
# [TODO][NERLA]: Implement the script to generate 5 secp256k1 user key pairs (MAX_USERS=5 in enclavestate.h right now)  
# Saves files to <user0_pubkey.bin, user0_prikey.bin> ...
# Save a list of pubkeys with the preamble "5\n" and one hexstring user pubkey per line
# The enclave public signing key is available AFTER initPVRA in: enclave_enc_pubkey.bin



# Placeholder user0 key
echo "728c48ee66b4229ca476914fc87130014f5bd5eda29116578b2fc2dca01f4b7eb88b77acc107d4136649c470de332962daf17eeead91e5b253fa9912caa94d11" | xxd -r -p > user0_pubkey.bin
echo "0a9f3adcd54ee2043315210dd6a4d2c8f90590733a227d6fc4a08724543a24e2" | xxd -r -p > user0_prikey.bin

# Placeholder for pubkeys list
# Run this if you need a sample of what the pubkeys.list should look like
echo -e "5\n728c48ee66b4229ca476914fc87130014f5bd5eda29116578b2fc2dca01f4b7eb88b77acc107d4136649c470de332962daf17eeead91e5b253fa9912caa94d11\na388161f5b0fd97c1d7cfac645c5552d67da1c4706688736d3f9a4866dcbdd4956cde955303477fe9eb5bf4617e08ca18eaaf1b7a58eecb96a9714e28a16e6c5\n86093073acda4891e1da447ee9661e32ede352998a8663174b5c2be43c995cdaa4fca5ea32322ab70cb60bba1fd45acff7afe70d076effe47dddd7f8d39d8a74\n54ffdd443c49155b45771a38680d9531b564eec830416ceee9a75189f4252f1712225efc807a0349c72eae337bf657aceddffacedf3598dde707701ab97f5412\ncb731cf5bb5f82298be5a7e80759b6a74c9ff5f48b8bc81da760eb49366857e40a9c59e552b5a0ac570b3aa1dce14fe1fab3d4c751ab9b033f0fc36bc28bdb49" > pubkeys.list







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


