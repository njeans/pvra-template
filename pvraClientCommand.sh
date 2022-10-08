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


echo "[client] Generating AES session key using ECDH"

python3 ../../gen_ecdh.py $1


echo -e "[client] Encrypting Command ${Blue}$3${NC}"

# format_command encrypts struct private_command which is the {<command_type>, <command_inputs>, <seqno>}
# to modify this executable, update ./applications/<APP_NAME>/format.c
# and run gcc format.c -o format_command
./format_command "$3" pt.bin > /dev/null

# encrypt_command is universal and does not really need modification
# it takes as input a plaintext formatted command <pt.bin> and the raw AES key <sessionAESkey.bin>
./encrypt_command pt.bin sessionAESkey.bin > /dev/null







echo -e "[client] Client->Host eCMD+eAESkey"

# concatenates <user0_pubkey.bin> to <encrypted_command.bin> for sending to host
cat $2 eCMD.bin > command.bin

# the host should be waiting for this connection
nc -N localhost 8080 < command.bin >/dev/null





# WAIT FOR CRESPONSE FROM ENCLAVE





echo "[client] Received cResponse: HTTP/1.1 200 OK\n" | nc -l -p 8080 -q 0 > cResponse.json

# parses the cResponse.json hexstring into a binary signature file <cResponse.sig> and signed message <cResponse.txt>
jq '.sig' cResponse.json | tr -d '\"' | xxd -r -p > cResponse.sig
jq '.msg' cResponse.json | tr -d '\"' | xxd -r -p > cResponse.txt




echo -n "[client] Verifying cResponse signature: "

# secp256k1 signature verification: <signingkey.pem> is enclave public signing key
openssl dgst -sha256 -verify signingkey.pem -signature cResponse.sig cResponse.txt


# prints the cResponse message that was signed (CAREFUL only readable for ASCII string messages)
echo -n -e "[client] cResponse: ${Cyan}"
cat cResponse.txt
echo -e "${NC}"
echo ""
