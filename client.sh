#!/bin/bash

### PVRA CLIENT BEHAVIOR ###




# [TODO][BULLETIN]: GET ias_report.json from bulletin board
#./pvraRA ias_report.json
cp ../signingkey.pem .

./pvraClientCommand.sh "0 0 0 0 0"

./pvraClientCommand.sh "1 0 0 1 0"

./pvraClientCommand.sh "0 0 0 2 0"

./pvraClientCommand.sh "1 0 0 3 0"
