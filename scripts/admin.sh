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
  exit 1
fi

#if [[ -z "${SGX_SPID}" ]];
#then
#  echo "Error: environment variable SGX_SPID not set."
#  exit
#fi
#
#if [[ -z "${IAS_PRIMARY_KEY}" ]];
#then
#  echo "Error: environment variable IAS_PRIMARY_KEY not set."
#  exit
#fi

if [[ -z "${NUM_USERS}" ]];
then
  echo "Error: environment variable NUM_USERS not set."
  exit 1
fi

if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit 1
fi

rm -rf "$PROJECT_ROOT/test_sgx/*"

test -d "$PROJECT_ROOT/test_sgx" || mkdir "$PROJECT_ROOT/test_sgx"
test -d "$PROJECT_ROOT/test_sgx/client" || mkdir "$PROJECT_ROOT/test_sgx/client"
test -d "$PROJECT_ROOT/test_sgx/host" || mkdir "$PROJECT_ROOT/test_sgx/host"

cd "$PROJECT_ROOT/test_sgx"

for var in $(eval echo "{0..$NUM_USERS}")
do
  test -d "$PROJECT_ROOT/test_sgx/client/user_$var" || mkdir "$PROJECT_ROOT/test_sgx/client/user_$var"
done

if [ -d "$PROJECT_ROOT/${APP_NAME}/src"  ] #todo add docker env variable
then
  echo "Docker: copying application files"
  cp $PROJECT_ROOT/src/appPVRA.* $PROJECT_ROOT/enclave/
else
  echo "Local: building"
  cd $PROJECT_ROOT && make clean && make
#  source ~/.venvs/pvra/bin/activate
fi

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

if [[ ${CCF_ENABLE} == "1" ]]; #TODO fix
then
  cp ../service_cert.pem ./host
  cp ../user0_cert.pem ./host
  cp ../user0_privk.pem ./host
fi

exit 


