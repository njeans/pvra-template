#!/bin/bash
set -e
if [ "$SGX_MODE" = "HW" ]; then
  echo "Deploying PVRA app in Hardware mode"
  docker-compose up enclave
else
  echo "Deploying PVRA app in Simulation mode"
  docker-compose up enclave-sim
fi
