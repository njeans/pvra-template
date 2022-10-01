#!/bin/bash

### PVRA CLIENT BEHAVIOR ###
#"1 0 0 1 0" is a VSC command: readable as commandType=1 (query), userID=0, test_result=0, seqNo=1, clientID=0 
# "0 8214 1.0 1.0 10 20 0 0 0" sample HeatMap command: readable as commandType=0 (addPersonalData), userID=8214, lat=1.0, lng=1.0, startTs=10, endTs=20, result=0(false/negative), seqNo=0, clientID=0



# [TODO][BULLETIN]: GET ias_report.json from bulletin board
#./pvraRA ias_report.json
cp ../signingkey.pem .

./pvraClientCommand.sh "0 1 1.0 1.0 5.0 5.0 0 0 0"
exit 0
./pvraClientCommand.sh "1 0 0 1 0"

./pvraClientCommand.sh "0 0 0 2 0"

./pvraClientCommand.sh "1 0 0 3 0"
