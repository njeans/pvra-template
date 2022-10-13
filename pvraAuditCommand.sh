#!/bin/bash

### PVRA HOST COMMAND SCRIPT ###

Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White
NC='\033[0m'

if [[ -z "${CCF_ENABLE}" ]]; 
then
  echo "Error: environment variable CCF_ENABLE not set."
  exit
fi


../../app/app --auditlogPVRA --enclave-path `pwd`/../../enclave/enclave.signed.so \
  --sealedState sealedState.bin \
  --auditlog auditlog.bin \
  --auditlogsig auditlog.sig 

key="$PROJECT_ROOT/test_sgx/signingkey.bin"
curr_dir=$(pwd)
data="$curr_dir/auditlog.bin"
sig="$curr_dir/auditlog.sig"

echo -n "[biPVRA] Verifying signed auditlog: "
#openssl dgst -sha256 -verify signingkey.pem -signature auditlog.sig auditlog.bin
python3 $PROJECT_ROOT/billboard/billboard.py admin_post_audit_data $data $sig $1
