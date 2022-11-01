#!/bin/bash
set -e
if [ "$SGX_MODE" = "SW" ]; then
  echo "Running in Simulation mode"
  docker-compose build enclave-sim
  docker-compose run --rm enclave-sim $1
else
  docker compose build enclave
  docker compose  run --rm enclave $1
fi