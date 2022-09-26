#!/bin/bash

### PVRA CLIENT BEHAVIOR ###
#"1 0 0 1 0" is a VSC command: readable as commandType=1 (query), userID=0, test_result=0, seqNo=1, clientID=0 



# [TODO][BULLETIN]: GET ias_report.json from bulletin board
#./pvraRA ias_report.json
cp ../signingkey.pem .

./pvraClientCommand.sh "0 0 0 0 0"

./pvraClientCommand.sh "1 0 0 1 0"

./pvraClientCommand.sh "0 0 0 2 0"

./pvraClientCommand.sh "1 0 0 3 0"
