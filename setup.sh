#!/bin/bash
# This script is run before make to prepare application files and CCF credentials

if [[ -z "${CCF_ENABLE}" ]]; 
then
  echo "Error: environment variable CCF_ENABLE not set."
  exit
fi

if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit
fi

POSITIONAL_ARGS=()

DEFAULT_APP_NAME=vsc

APP_NAME=""
CCF_PATH=$PROJECT_ROOT/shared/ccf/sandbox_common/

while [[ $# -gt 0 ]]; do
  case $1 in
    -a|--app)
      if [ "$2" == "" ]
      then
          echo "Error Usage: ./setup.sh -a|--app <APP_NAME> "
          exit 1
      fi
      APP_NAME="$2"
      shift # past argument
      shift # past value
      ;;     
    --default)
      echo "Defaulting to APP_NAME = $DEFAULT_APP_NAME"
      APP_NAME=$DEFAULT_APP_NAME
      shift # past argument
      ;;
    --clean)
      echo "Cleanup known application-specific files"
      rm $PROJECT_ROOT/enclave/appPVRA.*
      rm $PROJECT_ROOT/scripts/application.py
      make clean
      exit 0
      ;;
    -*|--*)
      echo "Unknown argument $1"
      exit 1
      ;;
    *)
      echo "Error Usage: ./setup.sh -a|--app <APP_NAME>"
      exit 1
      ;;
  esac
done

if [ "$APP_NAME" == "" ]
then
  echo "Defaulting to APP_NAME = $DEFAULT_APP_NAME"
  APP_NAME=$DEFAULT_APP_NAME
fi

if [ -d "$PROJECT_ROOT/applications/$APP_NAME/"  ]
then
  cp $PROJECT_ROOT/applications/$APP_NAME/*.h $PROJECT_ROOT/enclave/
  cp $PROJECT_ROOT/applications/$APP_NAME/*.c $PROJECT_ROOT/enclave/
  cp $PROJECT_ROOT/applications/$APP_NAME/*.h $PROJECT_ROOT/app/
  cp $PROJECT_ROOT/applications/$APP_NAME/*.py $PROJECT_ROOT/scripts/
else
  echo "Error: Application Directory $PROJECT_ROOT/applications/$APP_NAME/ does not exist."
fi
