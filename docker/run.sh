#!/bin/bash
set -e
if [ "$SGX_MODE" = "SW" ]; then
  echo "Running in Simulation mode"
  docker-compose run --rm enclave-sim $1
else
  echo "Running in Hardware mode"
  docker-compose run --rm enclave $1
fi
