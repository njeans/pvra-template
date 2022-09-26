#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#




#echo -e "HTTP/1.1 200 OK\n" | nc -l -p 8888 -q 0 > input.bin;


xxd -p cResponse.sig | tr -d '\n' > sig.hexstring
xxd -p cResponse.txt | tr -d '\n' > msg.hexstring
SIG=$(cat ./sig.hexstring)
MSG=$(cat ./msg.hexstring)
jq -n --arg sig $SIG --arg msg $MSG '{"sig": $sig, "msg": $msg}' > cResponse.json


#nc -N localhost 8080 < cResponse.json



jq '.sig' sample.json | tr -d '\"'
jq '.msg' sample.json | tr -d '\"'

#cat test.json | xxd -r -p > test.bin