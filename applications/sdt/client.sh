#!/bin/bash
set +x
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
# [TODO][AUDITEE]: VERILY ias_report.json and extract enclave signing key (very similar to auditee_extract.py once ias_report.json is available)

# Placeholder: copying extracted enclave signing key from admin environment
uid=$1
#class airplane is relatively closer to animal classes in Task 7 than in Task 3
# Reconstructed dimensions in Task 3 span a wider range than in Task 7
cp ../signingkey.pem .
cp ../signingkey.bin .
cp ../enclave_enc_pubkey.bin .
cp ../enclave_enc_pubkey.sig .

cat $PROJECT_ROOT/test_sgx/host/host.log
seq=0
#client num or uid is first argument
echo "[client] tid=0 add data"
./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "0 $uid $seq -i NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN " "omit_sig"
echo "[client] waiting for audit 1"
sleep 10
cat $PROJECT_ROOT/test_sgx/host/host.log

seq=1
echo "[client] tid=1 start recover"
./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "1 $uid $seq " "omit_sig"
echo "[client] waiting for audit 2"
sleep 10
cat $PROJECT_ROOT/test_sgx/host/host.log

seq=2
if [ "$2" != "" ]; then
    echo "[client] tid=3 cancel recover"
    ./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "3 $uid $seq " $2
    cp cResponse.json cResponseCancel.json
    seq=3
fi

echo "[client] waiting for audit 3"
sleep 10
cat $PROJECT_ROOT/test_sgx/host/host.log


echo "[client] tid=2 try complete recover"
./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "2 $uid $seq " "omit_sig"

cp cResponseCancel.json cResponse.json #so we can prove omission for the cancel message