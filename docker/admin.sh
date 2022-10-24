#!/bin/bash
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

set -e

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


if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit
fi

test -d "$PROJECT_ROOT/test_sgx" || mkdir "$PROJECT_ROOT/test_sgx"
test -d "$PROJECT_ROOT/client" || mkdir "$PROJECT_ROOT/client"
test -d "$PROJECT_ROOT/host" || mkdir "$PROJECT_ROOT/host"

rm -rf "*"
rm -rf "$PROJECT_ROOT/client/*"
rm -rf "$PROJECT_ROOT/host/*"

cd "$PROJECT_ROOT/test_sgx"

for var in $(eval echo "{0..$NUM_USERS}")
do
  test -d "$PROJECT_ROOT/client/user_$var" || mkdir "$PROJECT_ROOT/client/user_$var"
done
echo "trying to see somethin"

exit 1
if [ -d "$PROJECT_ROOT/src"  ]
then
  cp "$PROJECT_ROOT/src/appPVRA.*" "$PROJECT_ROOT/enclave/"
  cp "$PROJECT_ROOT/src/format_command" "$PROJECT_ROOT/test_sgx/format_command"
  cp "$PROJECT_ROOT/src/encrypt_command" "$PROJECT_ROOT/test_sgx/encrypt_command"
else
  echo "Error: Application Directory ./applications/$APP_NAME/ does not exist."
fi
\
### 0.1 SCS INIT: Request Freshness Tag for newly initialized PVRA-enclave (sets FT = 256b'00...00') ###

if [[ ${CCF_ENABLE} == "1" ]];
then 
  cp ../service_cert.pem .
  cp ../user0_cert.pem .
  cp ../user0_privk.pem .
  echo -n "[biPVRA] INITSCS Freshness Tag: "
  curl -s https://ccf:8000/app/scs/request -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "4", "init": "0000000000000000000000000000000000000000000000000000000000000000"}' > init.txt

  if [[ $(grep init.txt -e "true") ]] 
  then
    echo "success"
  else
    echo "Error: CCF NOT RUNNING LOCALLY."
    exit
  fi
fi

if [[ ${CCF_ENABLE} == "1" ]];
then
  cp ../service_cert.pem ./host
  cp ../user0_cert.pem ./host
  cp ../user0_privk.pem ./host
fi

exit 


