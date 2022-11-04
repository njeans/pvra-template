#!/bin/bash

set -e


if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit 1
fi

./copy.sh

cd $PROJECT_ROOT
make clean
make