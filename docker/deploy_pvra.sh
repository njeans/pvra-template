#!/bin/bash
set -e
sudo chown -R $USER $PROJECT_ROOT/shared/ccf_sandbox/user0*
sudo chown -R $USER $PROJECT_ROOT/shared/ccf_sandbox/member0*
if [ "$SGX_MODE" = "HW" ]; then
  echo "Deploying PVRA app in Hardware mode"
  docker-compose up enclave
else
  echo "Deploying PVRA app in Simulation mode"
  docker-compose up enclave-sim
fi
