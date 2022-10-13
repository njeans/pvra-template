#!/bin/bash

### PVRA CLIENT BEHAVIOR ###

### HEATMAP COMMAND CHEAT SHEET ###
# "<commandType> <userID> <lat> <lng> <startTs> <endTs> <result> <seqNo>" is an example HeatMap command
# commandType: (0=addPersonalData, 1=getHeatMap) 
# userID: (integer) some user identification that is NOT their user_pubkey
# lat: (float)
# lng: (float)
# startTs: (integer) UNIX timestamp?
# endTs: (integer) UNIX timestamp?
# result: (0=negative, 1=positive)
# seqNo: (integer) must be increasing by 1 for each subsequent command from the same client



# [TODO][NERLA]: GET ias_report.json from bulletin board
# [TODO][AUDITEE]: VERIFY ias_report.json and extract enclave signing key (very similar to auditee_extract.py once ias_report.json is available)

# Placeholder: copying extracted enclave signing key from admin environment

cp ../signingkey.pem .
cp ../signingkey.bin .
cp ../enclave_enc_pubkey.bin .
cp ../enclave_enc_pubkey.sig .
#client num is first argument

./pvraClientCommand.sh 0 user0_prikey.bin user0_pubkey.bin "0 1 1.0 1.0 5.0 5.0 0 0" $1