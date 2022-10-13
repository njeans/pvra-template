#!/bin/bash

### PVRA CLIENT BEHAVIOR ###

### VSC COMMAND CHEAT SHEET ###
# "<commandType> <userID> <test_result> <seqNo>" is an example VSC command
# commandType: (0=update, 1=query) 
# userID: (integer) some user identification that is NOT their user_pubkey
# test_result: (0=negative, 1=positive) only used in update command
# seqNo: (integer) must be increasing by 1 for each subsequent command from the same client



# [TODO][NERLA]: GET ias_report.json from bulletin board
# [TODO][AUDITEE]: VERIFY ias_report.json and extract enclave signing key (very similar to auditee_extract.py once ias_report.json is available)

# Placeholder: copying extracted enclave signing key from admin environment
cp ../signingkey.pem .



./pvraClientCommand.sh 0 user0_prikey.bin user0_pubkey.bin "0 0 0 0"
 
./pvraClientCommand.sh 0 user0_prikey.bin user0_pubkey.bin "1 0 0 1"

./pvraClientCommand.sh 0 user0_prikey.bin user0_pubkey.bin "0 0 0 2"

./pvraClientCommand.sh 0 user0_prikey.bin user0_pubkey.bin "1 0 0 3"
