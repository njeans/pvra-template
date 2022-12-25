#!/bin/bash
set -e


ccf_server=https://localhost:8546
ccf_cert_dir=$PROJECT_ROOT/shared/ccf_sandbox
only_status_code="-s -o /dev/null -w %{http_code}"

if [ "$SGX_MODE" = "HW" ]; then
  echo "Starting CCF sgx server"
  ccf_platform=sgx
else
  echo "Starting CCF virtual server"
  ccf_platform=virtual
fi

docker-compose up -d ccf0-$ccf_platform ccf1-$ccf_platform ccf2-$ccf_platform

echo -e "💤 Waiting for the CCF app frontend..."

max=100
total=20
sleep $total

set +e
# Using the same way as https://github.com/microsoft/CCF/blob/1f26340dea89c06cf615cbd4ec1b32665840ef4e/tests/start_network.py#L94
status="$(curl "$ccf_server/app/commit" --cacert "${ccf_cert_dir}/service_cert.pem" $only_status_code)"
while [ "200" != $status ]
do
    t=10
    sleep $t
    total=$((total + t))
    if  (( $total > $max )); then 
      curl "$ccf_server/app/commit" --cacert "${ccf_cert_dir}/service_cert.pem"
      echo "timeout exceeded exiting after $total seconds"
      exit 1
    fi
    status="$(curl "$ccf_server/app/commit" --cacert "${ccf_cert_dir}/service_cert.pem" $only_status_code)"
done

echo -e "CCF network started and ready!"
