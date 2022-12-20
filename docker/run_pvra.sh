#!/bin/bash
set -e
if [ "$SGX_MODE" = "SW" ]; then
  echo "Running PVRA app in Simulation mode"
  docker-compose run --rm enclave-sim $1
else
  echo "Running PVRA app in Hardware mode"
  docker-compose run --rm enclave $1
fi
