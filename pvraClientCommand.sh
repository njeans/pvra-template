#!/bin/bash

### PVRA CLIENT COMMAND SCRIPT ###

Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White
NC='\033[0m'


echo "[client] Generating and encrypting AES session key"
openssl rand -hex 16 | xxd -r -p > sessionAESkey.bin
openssl rsautl -encrypt -pubin -inkey enckey.dat -in sessionAESkey.bin > eAESkey.bin
echo -e "[client] Encrypting Command ${Blue}$1${NC}"
./format_command "$1" pt.bin > /dev/null
./encrypt_command pt.bin sessionAESkey.bin > /dev/null
echo "[client] Client->Host eCMD+eAESkey\n"


cat eAESkey.bin eCMD.bin > command.bin
nc -N localhost 8080 < command.bin >/dev/null


# WAIT FOR CRESPONSE FROM ENCLAVE
echo "[client] Received cResponse: HTTP/1.1 200 OK\n" | nc -l -p 8080 -q 0 > cResponse.json

jq '.sig' cResponse.json | tr -d '\"' | xxd -r -p > cResponse.sig
jq '.msg' cResponse.json | tr -d '\"' | xxd -r -p > cResponse.txt

echo -n "[client] Verifying cResponse signature: "
openssl dgst -sha256 -verify signingkey.pem -signature cResponse.sig cResponse.txt

echo -n -e "[client] cResponse: ${Cyan}"
cat cResponse.txt
echo -e "${NC}"
echo ""
