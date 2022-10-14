#!/bin/bash
NC='\033[0m'
Purple='\033[0;35m'


if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit
fi

cd $PROJECT_ROOT
./setup.sh -a $1
make
./admin.sh

if [ "$2" = "omit_sig" ]; then
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~Running auditing case for user using signature to prove omission~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Admin returns signature without including user data~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  cd $PROJECT_ROOT/test_sgx/host
  ./host.sh $2 &
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~User verifies signature and doesn't post data to bulletin board~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  cd $PROJECT_ROOT/test_sgx/client
  ./client.sh $2
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Admin does auditing~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  sleep 10
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~User proves data omission with admin signature~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  ./pvraClientAuditCommand.sh 0 sig
  exit 0
fi


if [ "$2" = "omit_data" ]; then
  echo -e "${Purple}~~~~~~~~~~~~~~Running auditing case for user using data posted on bulletin board to prove omission~~~~~~~~~~~~~~${NC}"
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~User post data to bulletin board without sending to admin~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  cd $PROJECT_ROOT/test_sgx/client
  ./client.sh "omit"
  cd $PROJECT_ROOT/test_sgx/host
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~Admin does not get data from bulletin board and does auditing~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  ./host.sh "omit" "omit"
  cd $PROJECT_ROOT/test_sgx/client
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~User proves data omission with data posted to bulletin board~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  ./pvraClientAuditCommand.sh 0 1 data
  exit 0
fi


if [ "$2" = "omit_user" ]; then
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~Running auditing case for admin getting user data posted on bulletin board~~~~~~~~~~~~~~~~~~~${NC}"
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~User post data to bulletin board without sending to admin~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  cd $PROJECT_ROOT/test_sgx/client
  ./client.sh "omit"
  cd $PROJECT_ROOT/test_sgx/host
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~Admin gets data from bulletin board and does auditing~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  ./host.sh "omit"
  cd $PROJECT_ROOT/test_sgx/client
  echo -e "${Purple}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Client auditing with data should fail~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
  ./pvraClientAuditCommand.sh 0 1 data
  exit 0
fi