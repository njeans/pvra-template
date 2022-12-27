#!/bin/bash

if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit 1
fi
ccf_server=https://localhost:8546
ccf_cert_dir=$PROJECT_ROOT/shared/ccf_sandbox
only_status_code="-s -o /dev/null -w %{http_code}"
sudo chown -R $USER $PROJECT_ROOT/shared/ccf_sandbox/user0*
sudo chown -R $USER $PROJECT_ROOT/shared/ccf_sandbox/member0*

if [ "$SGX_MODE" = "HW" ]; then
  echo "Building pvra in Hardware mode"
  pvra_mode=enclave
else
  echo "Building pvra in Simulation mode"
  pvra_mode=enclave-sim
fi

# Using the same way as https://github.com/microsoft/CCF/blob/1f26340dea89c06cf615cbd4ec1b32665840ef4e/tests/start_network.py#L94
echo -e "Making sure the CCF app frontend is up and the certs are fresh"

status="$(curl -s "$ccf_server/app/commit" --cacert "${ccf_cert_dir}/service_cert.pem" $only_status_code)"
echo $status
if [ "200" != $status ]; then
    curl -s "$ccf_server/app/commit" --cacert "${ccf_cert_dir}/service_cert.pem" | jq .
    echo -e "CCF app frontent end is not up...\ntry calling ./build_ccf.sh and ./deploy_ccf.sh"
    exit 1
fi


# echo -e "Changing permissions on CCF user0 cert/private keys at \n\t${ccf_cert_dir}/user0_cert.pem \n\t${ccf_cert_dir}/user0_privk.pem"
# sudo chmod +r $ccf_cert_dir/user0_cert.pem $ccf_cert_dir/user0_privk.pem

# echo "Hardcoding certificates" #todo add to dockerfile
# python3 $PROJECT_ROOT/scripts/utils.py gen_ca_bundle "${ccf_cert_dir}/service_cert.pem" $PROJECT_ROOT/enclave/ca_bundle.h

echo "Building PVRA image"
docker-compose build $pvra_mode