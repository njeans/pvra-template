#!/bin/bash

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
cp ../sealedState0.bin sealedState.bin

state_counter=$((state_counter+1))
./pvraHostCommand.sh $state_counter

state_counter=$((state_counter+1))
./pvraHostCommand.sh $state_counter

state_counter=$((state_counter+1))
./pvraHostCommand.sh $state_counter

state_counter=$((state_counter+1))
./pvraHostCommand.sh $state_counter


: '
while true
do
	./pvraHostCommand.sh $state_counter
	state_counter=$((state_counter+1))
done
'
