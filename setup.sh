#!/bin/bash
# This script is run before make to prepare application files

if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit
fi

scs_dir=$PROJECT_ROOT/counter-service
wolfssl_dir=$PROJECT_ROOT/trustedLib/wolfssl
if [[ -z "$(ls -A $scs_dir)" ||  -z "$(ls -A $wolfssl_dir)" ]]; then
  echo "Setting up submodules"
  git submodule update --init
fi

if [ ! -f "$wolfssl_dir/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a" ]; then
  echo "Building wolfssl"
  cd $wolfssl_dir/IDE/LINUX-SGX
  SGX_MODE=SIM SGX_PRERELEASE=0 SGX_DEBUG=1 make -f $PROJECT_ROOT/trustedLib/wolfssl_sgx_t_static.mk HAVE_WOLFSSL_SP=1
  cp libwolfssl.sgx.static.lib.a libwolfssl.sgx.static.lib_sim.a
  SGX_MODE=HW SGX_PRERELEASE=1 SGX_DEBUG=0 make -f $PROJECT_ROOT/trustedLib/wolfssl_sgx_t_static.mk HAVE_WOLFSSL_SP=1
fi

POSITIONAL_ARGS=()

DEFAULT_APP_NAME=vsc

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
else 
  echo "Setup $APP_NAME"
fi
if [ -d "$PROJECT_ROOT/applications/$APP_NAME/"  ]
then
  cp $PROJECT_ROOT/applications/$APP_NAME/*.h $PROJECT_ROOT/enclave/
  cp $PROJECT_ROOT/applications/$APP_NAME/*.c $PROJECT_ROOT/enclave/
  cp $PROJECT_ROOT/applications/$APP_NAME/*.h $PROJECT_ROOT/untrusted/
  cp $PROJECT_ROOT/applications/$APP_NAME/*.py $PROJECT_ROOT/demo/
else
  echo "Error: Application Directory $PROJECT_ROOT/applications/$APP_NAME/ does not exist."
fi
