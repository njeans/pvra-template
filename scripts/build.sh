#!/bin/bash

set -e


if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit 1
fi


if [[ ${deployment_location} == "DOCKER" ]];
then
  cp $PROJECT_ROOT/src/appPVRA.* $PROJECT_ROOT/enclave
else

  if [[ -z "${APP_NAME}" ]];
  then
    echo "Error: environment variable APP_NAME not set."
    exit 1
  fi

  cp $PROJECT_ROOT/applications/$APP_NAME/appPVRA.* $PROJECT_ROOT/enclave/

fi

cd $PROJECT_ROOT
make clean
make