#!/bin/bash
set -e
sudo chown -R $USER $PROJECT_ROOT/shared/ccf_sandbox/user0*
sudo chown -R $USER $PROJECT_ROOT/shared/ccf_sandbox/member0*
if [ "$SGX_MODE" = "SW" ]; then
  echo "Running in Simulation mode"
  docker-compose run --rm enclave-sim $@
else
  echo "Running in Hardware mode"
  docker-compose run --rm enclave $@
fi
