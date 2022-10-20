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

state_counter=$1
mode=$2
echo "pvraAuditCommand sc: $1 mode: [$2]"

if [ "$mode" != "omit" ]; then
  echo "[biPVRA] Getting data from bulletin board"
  # wait for data to be commited to bb
  sleep 3
  CMDPATH="tmp_ecmds"
  mkdir $CMDPATH
  python3 $PROJECT_ROOT/billboard/billboard.py admin_get_bb_data $CMDPATH $3

  CMDFILES=$(ls "$CMDPATH")

  echo "[biPVRA] Posting data from bulletin board $CMDFILES"

  for f in $CMDFILES
  do
    echo "[biPVRA] Forwarding data in $CMDPATH/$f"
    cp "$CMDPATH/$f" command.bin
    ./pvraHostCommand.sh $state_counter local
    state_counter=$((state_counter+1))
  done
  rm -rf $CMDPATH
fi

../../app/app --auditlogPVRA --enclave-path `pwd`/../../enclave/enclave.signed.so \
  --sealedState sealedState.bin \
  --auditlog auditlog.bin \
  --auditlogsig auditlog.sig \
  --sealedOut sealedOut.bin

filename="sealedState$state_counter.bin"
cp sealedOut.bin $filename
mv sealedOut.bin sealedState.bin



key="$PROJECT_ROOT/test_sgx/signingkey.bin"
curr_dir=$(pwd)
data="$curr_dir/auditlog.bin"
sig="$curr_dir/auditlog.sig"

echo -n "[biPVRA] Verifying signed auditlog: "
#openssl dgst -sha256 -verify signingkey.pem -signature auditlog.sig auditlog.bin
python3 $PROJECT_ROOT/billboard/billboard.py admin_post_audit_data $data $sig
