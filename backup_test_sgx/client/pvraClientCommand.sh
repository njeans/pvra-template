#!/bin/bash

### PVRA CLIENT COMMAND SCRIPT ###




cp ../signingkey.pem .

echo "[client] Generating and encrypting AES session key"
openssl rand -hex 16 | xxd -r -p > sessionAESkey.bin
openssl rsautl -encrypt -pubin -inkey enckey.dat -in sessionAESkey.bin > eAESkey.bin
echo "[client] Encrypting Command $1"
./encrypt_command 0 0 0 0 0 sessionAESkey.bin > /dev/null
echo "[client] Client->Host eCMD+eAESkey\n"


cat eAESkey.bin eCMD.bin > command.bin
nc -N localhost 8080 < command.bin


# WAIT FOR CRESPONSE FROM ENCLAVE
echo "[client] Received cResponse: HTTP/1.1 200 OK\n" | nc -l -p 8080 -q 0 > cResponse.json

jq '.sig' cResponse.json | tr -d '\"' | xxd -r -p > cResponse.sig
jq '.msg' cResponse.json | tr -d '\"' | xxd -r -p > cResponse.txt

echo -n "\n[client] Verifying cResponse signature: "
openssl dgst -sha256 -verify signingkey.pem -signature cResponse.sig cResponse.txt

echo -n "[client] cResponse: "
cat cResponse.txt

