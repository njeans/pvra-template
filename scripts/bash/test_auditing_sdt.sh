#!/bin/bash
NC='\033[0m'
Purple='\033[0;35m'
set -e

if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit
fi

if [ "$1" = "" ]; then
  echo "Error: first argument must be application name"
  exit
fi


if [ "$2" = "" ]; then
  echo "Error: scenario name"
  echo "    failure cases {omit_sig, omit_data}"
  echo "    success cases {sig, data}"
  exit
fi


if [ "$3" = "" ]; then
  echo "Error: third argument must be user id"
  exit
fi

cd $PROJECT_ROOT
./setup.sh -a $1
#make clean #todo uncomment
make
./admin.sh

state_counter=0
HOST_PID=0
uid=$3
seq=0

host_1 () {
  cd $PROJECT_ROOT/test_sgx/host
  cp ../sealedState0.bin sealedState.bin
  echo "[host] waiting.. 1"
  ./pvraHostCommand.sh $state_counter &> host.log &
  HOST_PID=$!
  echo "kill $HOST_PID"
  sleep 1
}

client_1 () {
    cd $PROJECT_ROOT/test_sgx/client
    cp ../signingkey.pem .
    cp ../signingkey.bin .
    cp ../enclave_enc_pubkey.bin .
    cp ../enclave_enc_pubkey.sig .

    echo "_____________________________"
    cat $PROJECT_ROOT/test_sgx/host/host.log
    echo "_____________________________"

    echo "[client] tid=0 add data"
    ./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "0 $uid $seq -i NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN " "omit_sig"
    sleep 3
    cat $PROJECT_ROOT/test_sgx/host/host.log
    set +e
    kill $HOST_PID
    set -e
}

host_2() {
    cd $PROJECT_ROOT/test_sgx/host
    echo "[host] running auditing.. 1"
    state_counter=$((state_counter+1))
    ./pvraAuditCommand.sh $state_counter

    echo "[host] waiting.. 2"
    state_counter=$((state_counter+1))
    ./pvraHostCommand.sh $state_counter  &> host.log &
    HOST_PID=$!
    echo "kill $HOST_PID"
  sleep 1
}

client_2() {
    cd $PROJECT_ROOT/test_sgx/client
    echo "[client] tid=3 start recover"
    seq=$((seq+1))
    ./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "3 $uid $seq " "omit_sig"
    sleep 3
    cat $PROJECT_ROOT/test_sgx/host/host.log
    set +e
    kill $HOST_PID
    set -e
}

host_3() {

    cd $PROJECT_ROOT/test_sgx/host
    echo "[host] running auditing.. 2"
    state_counter=$((state_counter+1))
    ./pvraAuditCommand.sh $state_counter

    echo "[host] waiting.. 3 $1"
    if [ "$1" != "omit" ]; then
        state_counter=$((state_counter+1))
        ./pvraHostCommand.sh $state_counter $1 &> host.log &
        HOST_PID=$!
        echo "kill $HOST_PID"
        sleep 1
    else
        echo "[host] not waiting $1 .."
        echo "" > host.log
    fi
}

client_3() {
    cd $PROJECT_ROOT/test_sgx/client
    echo "[client] tid=1 cancel recover $1"
    seq=$((seq+1))
    ./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "1 $uid $seq " $1
    cp cResponse.json cResponseCancel.json
    sleep 3
    cat $PROJECT_ROOT/test_sgx/host/host.log
    set +e
    kill $HOST_PID
    set -e
}

host_4() {
  cd $PROJECT_ROOT/test_sgx/host
  echo "[host] running auditing.. 3 $1"
  state_counter=$((state_counter+1))
  ./pvraAuditCommand.sh $state_counter $1
  if [ "$1" != "omit" ]; then
    state_counter=$((state_counter+1))
  fi

  echo "[host] waiting.. last"
  state_counter=$((state_counter+1))
  ./pvraHostCommand.sh $state_counter &> host.log &
  HOST_PID=$!
  echo "kill $HOST_PID"
  sleep 2
}

client_4() {
    cd $PROJECT_ROOT/test_sgx/client
    echo "[client] tid=4 try complete recover"
    seq=$((seq+1))
    ./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "4 $uid $seq " "omit_sig"
    #so we can prove omission for the cancel message
    cp cResponseCancel.json cResponse.json
    sleep 3
    cat $PROJECT_ROOT/test_sgx/host/host.log
    set +e
    kill $HOST_PID
    set -e
}


if [ "$2" = "omit_sig" ]; then
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~Running auditing case for app $1 user using signature to prove omission with user $3~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
#  ./host.sh $2 &> host.log &
  host_1
  client_1
  host_2
  client_2

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Admin returns signature without including user data~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  host_3 "omit_sig"

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~User verifies signature and doesn't post data to bulletin board~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
#  ./client.sh $3  $2
  client_3 "omit_sig"

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Admin does auditing and does not get data from bulletin board~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  host_4 "omit"

  client_4

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~User proves data omission with admin signature~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  cd $PROJECT_ROOT/test_sgx/client
  ./pvraClientAuditCommand.sh sig $uid
  exit 0
fi


if [ "$2" = "omit_data" ]; then
  echo -e "${Purple}~~~~~~~~~~~~~~Running auditing case for app $1 user using data posted on bulletin board to prove omission with user $3~~~~~~~~~~~~~~${NC}"
#  ./host.sh "omit" "omit" &> host.log &

  host_1
  client_1
  host_2
  client_2

  host_3 "omit"

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~User post data to bulletin board without sending to admin~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
#  ./client.sh  $3 "omit"
  client_3 "omit"

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~Admin does not get data from bulletin board and does auditing~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  host_4 "omit"

  client_4

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~User proves data omission with data posted to bulletin board~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  ./pvraClientAuditCommand.sh data $uid 3
  exit 0
fi


if [ "$2" = "data" ]; then
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~Running auditing case for app $1 no omission backup case with data with user $3~~~~~~~~~~~~~~~~~~~${NC}"
#  ./host.sh "omit" &> host.log &
  host_1
  client_1
  host_2
  client_2

  host_3 "omit"

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~User post data to bulletin board without sending to admin~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  cd $PROJECT_ROOT/test_sgx/client
#  ./client.sh  $3 "omit"
  client_3 "omit"

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~Admin gets data from bulletin board and does auditing~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  host_4

  client_4

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Client auditing with data should fail~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  ./pvraClientAuditCommand.sh data $uid 3
  exit 0
fi

if [ "$2" = "sig" ]; then
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~Running auditing case for app $1 no omission fast case with signature with user $3~~~~~~~~~~~~~~~~~~~${NC}"
  cd $PROJECT_ROOT/test_sgx/host
#  ./host.sh &> host.log &
  host_1
  client_1
  host_2
  client_2

  host_3

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~User verifies signature and doesn't post data to bulletin board~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
#  ./client.sh  $3 $2

  client_3 "omit_sig"

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~Admin gets data from bulletin board and does auditing~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"

  host_4
  client_4

#  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Client auditing with signature should fail~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
#  ./pvraClientAuditCommand.sh sig $uid
  exit 0
fi

if [ "$2" = "rec" ]; then
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~Running auditing case for app $1 no omission fast case with signature with user $3~~~~~~~~~~~~~~~~~~~${NC}"
  cd $PROJECT_ROOT/test_sgx/host
#  ./host.sh &> host.log &
  host_1
  client_1
  host_2
  client_2

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~User verifies signature and doesn't post data to bulletin board~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
#  ./client.sh  $3 $2

  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~Admin gets data from bulletin board and does auditing~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"

  host_4
  client_4

#  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Client auditing with signature should fail~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
#  ./pvraClientAuditCommand.sh sig $uid
  exit 0
fi

echo "Error: scenario name $2 not found:"
echo "    failure cases {omit_sig, omit_data}"
echo "    success cases {sig, data, rec}"
exit 123

#
cd $PROJECT_ROOT
./setup.sh -a sdt
make
./admin.sh
cd $PROJECT_ROOT/test_sgx/host
./host.sh "omit" > host.log &
cd $PROJECT_ROOT/test_sgx/client

cp ../signingkey.pem .
cp ../signingkey.bin .
cp ../enclave_enc_pubkey.bin .
cp ../enclave_enc_pubkey.sig .
uid=0
seq=0
cat $PROJECT_ROOT/test_sgx/host/host.log
./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "0 $uid $seq -i NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN " "omit_sig"

seq=1
cat $PROJECT_ROOT/test_sgx/host/host.log
./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "1 $uid $seq " "omit_sig"

seq=2
cat $PROJECT_ROOT/test_sgx/host/host.log
./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "3 $uid $seq " "omit"
cp cResponse.json cResponseCancel.json

seq=3
cat $PROJECT_ROOT/test_sgx/host/host.log
./pvraClientCommand.sh $uid "user"$uid"_prikey.bin" "user"$uid"_pubkey.bin" "2 $uid $seq " "omit_sig"


cat $PROJECT_ROOT/test_sgx/host/host.log
kill %1
ps -ef | grep ost


ps -ef | grep host.sh
./client.sh 0 "omit_sig"
cat $PROJECT_ROOT/test_sgx/host/host.log
