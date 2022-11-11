#!/bin/bash

set -e


if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit 1
fi


if [[ ${deployment_location} == "DOCKER" ]];
then
  cp $PROJECT_ROOT/src/*.py $PROJECT_ROOT/scripts/
  cp $PROJECT_ROOT/src/*.c $PROJECT_ROOT/enclave
  cp $PROJECT_ROOT/src/*.h $PROJECT_ROOT/enclave
  cp $PROJECT_ROOT/src/*.h $PROJECT_ROOT/app
else

  if [[ -z "${APP_NAME}" ]];
  then
    echo "Error: environment variable APP_NAME not set."
    exit 1
  fi

  cp $PROJECT_ROOT/applications/$APP_NAME/*.py $PROJECT_ROOT/scripts/
  cp $PROJECT_ROOT/applications/$APP_NAME/*.c $PROJECT_ROOT/enclave/
  cp $PROJECT_ROOT/applications/$APP_NAME/*.h $PROJECT_ROOT/enclave/
  cp $PROJECT_ROOT/applications/$APP_NAME/*.h $PROJECT_ROOT/app/

fi