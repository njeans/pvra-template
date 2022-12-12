#!/bin/bash
set -e

ccf_server=https://localhost:8546
ccf_cert_dir=$PROJECT_ROOT/shared/ccf/sandbox_common
only_status_code="-s -o /dev/null -w %{http_code}"

if [ "$SGX_MODE" = "SW" ]; then
  echo "Building in Simulation mode"
  ccf_platform=ccf-virtual
  pvra_platform=enclave-sim
else
  echo "Building in Hardware mode"
  ccf_platform=ccf-sgx
  pvra_mode=enclave
fi

echo "Building and Starting CCF server"
docker-compose build $ccf_platform
docker-compose up -d $ccf_platform

# Using the same way as https://github.com/microsoft/CCF/blob/1f26340dea89c06cf615cbd4ec1b32665840ef4e/tests/start_network.py#L94
# There is a side effect here in the case of the sandbox as it creates the 'workspace/sandbox_common' everytime
# it starts up. The following condition not only checks that this pem file has been created, it also checks it
# is valid. Don't be caught out by the folder existing from a previous run.
echo -e "💤 Waiting for the CCF app frontend...\n\t...get up and stretch"

max=500
total=350
sleep $total

set +e

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

set -e

# echo -e "Changing permissions on CCF user0 cert/private keys at \n\t${ccf_cert_dir}/user0_cert.pem \n\t${ccf_cert_dir}/user0_privk.pem"
# sudo chmod +r $ccf_cert_dir/user0_cert.pem $ccf_cert_dir/user0_privk.pem

# echo "Hardcoding certificates" #todo add to dockerfile
# python3 $PROJECT_ROOT/scripts/utils.py gen_ca_bundle "${ccf_cert_dir}/service_cert.pem" $PROJECT_ROOT/enclave/ca_bundle.h

echo "Building PVRA image"
docker-compose build $pvra_platform