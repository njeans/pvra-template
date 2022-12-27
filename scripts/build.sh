#!/bin/bash

set -e

if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit 1
fi

cd $PROJECT_ROOT/scripts
./copy.sh
cd $PROJECT_ROOT
make clean
file=$PROJECT_ROOT/enclave/ca_bundle.sh
if [[ ! -f "$file" ]]
then
  if [[ ${CCF_ENABLE} == "1" ]];
  then
    echo "Generating enclave/ca_bundle.sh file"
    python $PROJECT_ROOT/demo/utils.py gen_ca_bundle
  fi
fi
make $1