#!/bin/bash
set -e

ccf_server=https://localhost:8546
ccf_cert_dir=$PROJECT_ROOT/shared/ccf_sandbox
only_status_code="-s -o /dev/null -w %{http_code}"

if [ "$SGX_MODE" = "HW" ]; then
  echo "Building and Starting CCF sgx server"
  ccf_platform=sgx
else
  echo "Building and Starting CCF virtual server"
  ccf_platform=virtual
fi

docker-compose build ccf0-$ccf_platform