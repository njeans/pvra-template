#!/bin/bash
set -e
### PVRA HOST PROTOCOL ###


if [[ -z "${CCF_ENABLE}" ]]; 
then
  echo "Error: environment variable CCF_ENABLE not set."
  exit
fi

# set CCF FT to "0..0" indicating newly initialized FT
if [[ ${CCF_ENABLE} == "1" ]];
then 
curl https://127.0.0.1:8000/app/scs/request -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": "28", "init": "0000000000000000000000000000000000000000000000000000000000000000"}'
fi
# state_counter is appended to sealedState*.bin to save history of sealed states
state_counter=0
audit_num=1
cp ../sealedState0.bin sealedState.bin

echo "[host] waiting.. 1"

state_counter=$((state_counter+1))
./pvraHostCommand.sh $state_counter

state_counter=$((state_counter+1))
./pvraAuditCommand.sh $audit_num $state_counter $2


echo "host waiting.. 2"
state_counter=$((state_counter+1))
./pvraHostCommand.sh $state_counter

audit_num=$((audit_num+1))
state_counter=$((state_counter+1))
./pvraAuditCommand.sh $audit_num $state_counter $2


echo "host waiting.. 3 mode:[$1][$2]"
if [ "$1" != "omit" ]; then
  state_counter=$((state_counter+1))
  ./pvraHostCommand.sh $state_counter $1
else
  sleep 5
  echo "[host] 3 not received skipping"
fi

state_counter=$((state_counter+1))
audit_num=$((audit_num+1))
./pvraAuditCommand.sh $audit_num $state_counter $2


echo "host waiting.. 4"
state_counter=$((state_counter+1))
./pvraHostCommand.sh $state_counter

audit_num=$((audit_num+1))
./pvraAuditCommand.sh $audit_num $state_counter $2

# Requesting the auditlog is implemented as a seperate lightweight ecall that doesn't change the enclave state
# auditlogPVRA ecall currently does not use audit_version_no, instead it just dumps the entire audit log (we can change later this doesn't seem high priority)
# the "blob" that is signed is {hash(eCMD0) || cmd0_userpubkey || ... || hash(eCMDN) || cmdN_userpubkey}
# there are print statements in the ecall for a better look




# EVENTUALLY the host should be implemented in a while loop handling commands endlessly, and potentially buffering requests
: '
while true
do
	./pvraHostCommand.sh $state_counter
	state_counter=$((state_counter+1))
done
'
