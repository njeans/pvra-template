#!/bin/bash
set -e
if [ "$SGX_MODE" = "SW" ]; then
  echo "Building in Simulation mode"
  docker-compose build enclave-sim
else
  echo "Building in Hardware mode"
  docker-compose build enclave
fi
