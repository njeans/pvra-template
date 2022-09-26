#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#


echo -e "HTTP/1.1 200 OK\n[server] Received Command." | nc -l -p 8080 -q 0 > command.bin
dd count=256 if=command.bin of=eAESkey.bin bs=1
dd skip=256 if=command.bin of=eCMD.bin bs=1
printf "[bcPVRA] Host<-Client eAESkey+eCMD\n"


./pvraProcessCommand.sh


state_counter=$((state_counter+1))
filename="sealedState$1.bin" 
cp sealedOut.bin $filename
mv sealedOut.bin sealedState.bin


xxd -p cResponse.sig | tr -d '\n' > sig.hexstring
xxd -p cResponse.txt | tr -d '\n' > msg.hexstring
SIG=$(cat ./sig.hexstring)
MSG=$(cat ./msg.hexstring)
jq -n --arg sig $SIG --arg msg $MSG '{"sig": $sig, "msg": $msg}' > cResponse.json


echo "[bcPVRA] Host->Client cResponse"
nc -N localhost 8080 < cResponse.json

