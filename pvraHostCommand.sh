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

if [ "$2" = "local" ]; then
  echo "adding a local command.bin"
    dd count=64 if=command.bin of=pubkeyCMD.bin bs=1 >/dev/null 2>&1
    dd skip=64 if=command.bin of=eCMD.bin bs=1 >/dev/null 2>&1
else
  echo "[server] Received Command: HTTP/1.1 200 OK" | nc -l -p 8080 -q 0 > command.bin;
  dd count=64 if=command.bin of=pubkeyCMD.bin bs=1 >/dev/null 2>&1
  dd skip=64 if=command.bin of=eCMD.bin bs=1 >/dev/null 2>&1
  echo "[bcPVRA] Host<-Client eAESkey+eCMD"
fi

echo "[bcPVRA] Host->SCS updateFT(...)"


cat sealedState.bin eCMD.bin > se.bin 
openssl dgst -r -sha256 se.bin | head -c 64 > se.hash
value=`cat se.hash`
final="{\"id\": \"28\", \"commit\": \"${value}\"}"

if [[ ${CCF_ENABLE} == "1" ]];
then 
  retry_scs=1
  while [ $retry_scs == 1 ]
  do

    curl -s https://127.0.0.1:8000/app/scs/update -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary "$final" -o scsupdate.txt

    if [[ ! $(grep -e "error" scsupdate.txt) ]]; then
      retry_scs=0
    fi

  done


: '
retry_scs=1
while [ $retry_scs ]
do
if curl -s https://127.0.0.1:8000/app/scs/update -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary "$final" -o scsupdate.txt; then
	if [[ $(grep -e "error" scsupdate.txt) ]]; then
		echo "grep ERROR"
		retry_scs=0
	fi
fi
done
'


cat scsupdate.txt | grep -ioE 'signature":".*}' | cut -d "\"" -f3 | sed 's/\\n/\n/g'  > signedFT.txt
cat scsupdate.txt | grep -ioE 'signature":".*}' | cut -d "\"" -f7  > FT.txt
base64 -d signedFT.txt > signedFT.bin

else
  cp ../../sampleFT.txt FT.txt
  cp ../../samplesignedFT.txt signedFT.txt
  base64 -d signedFT.txt > signedFT.bin
fi

printf "[bcPVRA] Host<-SCS signedFT = "
cat FT.txt

../../app/app --commandPVRA --enclave-path `pwd`/../../enclave/enclave.signed.so \
  --sealedState sealedState.bin \
  --signedFT signedFT.bin \
  --FT FT.txt \
  --eCMD eCMD.bin \
  --eAESkey pubkeyCMD.bin \
  --cResponse cResponse.txt \
  --cRsig cResponse.sig \
  --sealedOut sealedOut.bin

filename="sealedState$1.bin"
cp sealedOut.bin $filename
mv sealedOut.bin sealedState.bin

xxd -p cResponse.sig | tr -d '\n' > sig.hexstring
xxd -p cResponse.txt | tr -d '\n' > msg.hexstring
SIG=$(cat ./sig.hexstring)
MSG=$(cat ./msg.hexstring)

python3 $PROJECT_ROOT/billboard/billboard.py admin_sign_confirmation pubkeyCMD.bin eCMD.bin sig_admin.hexstring msg_admin.hexstring
MSG_ADMIN=$(cat ./msg_admin.hexstring)
SIG_ADMIN=$(cat ./sig_admin.hexstring)

jq -n --arg sig $SIG --arg msg $MSG  --arg sig_a $SIG_ADMIN --arg msg_a $MSG_ADMIN '{"sig": $sig, "msg": $msg, "sig_admin": $sig_a, "msg_admin": $msg_a}' > cResponse.json

if [ "$2" = "local" ]; then
  echo "todo upload cResponse to billboard?" #todo
else
  echo "[bcPVRA] Host->Client cResponse"
  nc -N localhost 8080 < cResponse.json >/dev/null
  echo ""
fi
