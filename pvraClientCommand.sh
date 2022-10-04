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

# [TODO][NERLA]: Python Script to generate Shared Secret using ECDH

# The two source files would be: user0_prikey.bin and enclave_enc_pubkey.bin
# Both are raw byte dump of secp256k1 keys 
# (NOT 100% sure about the endianess) 
# I suspect they are little endian because auditee_extract.py assumes little endian and the signature verification is PASSING
# I attempted something in client_ecdh.py but figured you would be faster at implementing this
# ./client_ecdh.py user0_prikey.bin enclave_enc_pubkey.bin



# Placeholder Shared Secret between enclave and user0: 8ccb97f8c11de97bbd707b735fed37059bc3d1de7dc418958a38b4e51bceaab8
# This works because DETERMINISTIC_ENC_KEY=1 in initPVRA.c (making enclave encryption key fixed)
# And the user0_key is hardcoded in admin.sh

# Not 100% sure what the protocol is to generate AES-128 key from this, using Top 128 bits for now
echo "8ccb97f8c11de97bbd707b735fed3705" | xxd -r -p > sessionAESkey.bin
      





echo -e "[client] Encrypting Command ${Blue}$2${NC}"

# format_command encrypts struct private_command which is the {<command_type>, <command_inputs>, <seqno>}
# to modify this executable, update ./applications/<APP_NAME>/format.c
# and run gcc format.c -o format_command
./format_command "$2" pt.bin > /dev/null

# encrypt_command is universal and does not really need modification
# it takes as input a plaintext formatted command <pt.bin> and the raw AES key <sessionAESkey.bin>
./encrypt_command pt.bin sessionAESkey.bin > /dev/null







echo -e "[client] Client->Host eCMD+eAESkey"

# concatenates <user0_pubkey.bin> to <encrypted_command.bin> for sending to host
cat $1 eCMD.bin > command.bin

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
