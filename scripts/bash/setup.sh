#!/bin/bash
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#


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
DEFAULT_CCF_PATH=$PROJECT_ROOT/ccf-2.0.1/build/workspace/sandbox_common/

APP_NAME=""
CCF_PATH=""

if [ $# == 0 ]
then
  echo "Defaulting to APP_NAME = $DEFAULT_APP_NAME"
  APP_NAME=$DEFAULT_APP_NAME
  echo "Defaulting to CCF_PATH = $DEFAULT_CCF_PATH"
  CCF_PATH=$DEFAULT_CCF_PATH
fi

while [[ $# -gt 0 ]]; do
  case $1 in
    -a|--app)
      if [ "$2" == "" ]
      then
          echo "Error Usage: ./setup.sh -a|--app <APP_NAME> -c|--ccf <CCF_PATH>"
          exit 1
      fi
      APP_NAME="$2"
      shift # past argument
      shift # past value
      ;;
    -c|--ccf)
      if [ "$2" == "" ]
      then
          echo "Error Usage: ./setup.sh -a|--app <APP_NAME> -c|--ccf <CCF_PATH>"
          exit 1
      fi
      CCF_PATH="$2"
      shift # past argument
      shift # past value
      ;;      
    --default)
      echo "Defaulting to APP_NAME = $DEFAULT_APP_NAME"
      APP_NAME=$DEFAULT_APP_NAME
      echo "Defaulting to CCF_PATH = $DEFAULT_CCF_PATH"
      CCF_PATH=$DEFAULT_CCF_PATH
      shift # past argument
      ;;
    --clean)
      echo "Removing ALL setup.sh application-specific and CCF-specific files"
      rm $PROJECT_ROOT/enclave/appPVRA.*
      rm $PROJECT_ROOT/scripts/application.py
      rm ./service_cert.pem
      rm ./user0_cert.pem
      rm ./user0_privk.pem
      exit 0
      ;;
    -*|--*)
      echo "Unknown argument $1"
      exit 1
      ;;
    *)
      echo "Error Usage: ./setup.sh -a|--app <APP_NAME> -c|--ccf <CCF_PATH>"
      exit 1
      ;;
  esac
done

if [ "$APP_NAME" == "" ]
then
  echo "Defaulting to APP_NAME = $DEFAULT_APP_NAME"
  APP_NAME=$DEFAULT_APP_NAME
fi

if [ "$CCF_PATH" == "" ]
then
  echo "Defaulting to CCF_PATH = $DEFAULT_CCF_PATH"
  CCF_PATH=$DEFAULT_CCF_PATH
fi

if [ -d "$PROJECT_ROOT/applications/$APP_NAME/"  ]
then
  cp $PROJECT_ROOT/applications/$APP_NAME/*.c $PROJECT_ROOT/enclave/
  cp $PROJECT_ROOT/applications/$APP_NAME/*.h $PROJECT_ROOT/enclave/
  echo "COMPOSE_PROJECT_NAME=$APP_NAME" > $PROJECT_ROOT/docker/.env
  echo "APP_NAME=$APP_NAME" >> $PROJECT_ROOT/docker/.env
else
  echo "Error: Application Directory $PROJECT_ROOT/applications/$APP_NAME/ does not exist."
fi

if [ -d "$CCF_PATH"  ] #TODO fix
then
  if [[ ${CCF_ENABLE} == "1" ]];
  then
    cp $CCF_PATH/service_cert.pem .
    cp $CCF_PATH/user0_cert.pem .
    cp $CCF_PATH/user0_privk.pem .
  fi
else
  echo "Error: CCF Credentials Directory $CCF_PATH does not exist."
fi

