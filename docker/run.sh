#!/bin/bash
set -e
if [ "$SGX_MODE" = "SW" ]; then
  echo "Running in Simulation mode"
  docker-compose -f docker-compose-sim.yml build enclave
  docker-compose -f docker-compose-sim.yml run --rm enclave $1
else
  docker-compose  build enclave
  docker-compose  run --rm enclave $1
fi