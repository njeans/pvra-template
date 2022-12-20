#!/bin/bash
set -e
set +x

ccf_server=https://localhost:8546
ccf_cert_dir=$PROJECT_ROOT/shared/ccf_sandbox
only_status_code="-s -o /dev/null -w %{http_code}"

if [ "$SGX_MODE" = "SW" ]; then
  echo "Building in Simulation mode"
  pvra_mode=enclave-sim
else
  echo "Building in Hardware mode"
  pvra_mode=enclave
fi

# Using the same way as https://github.com/microsoft/CCF/blob/1f26340dea89c06cf615cbd4ec1b32665840ef4e/tests/start_network.py#L94
# There is a side effect here in the case of the sandbox as it creates the 'workspace/sandbox_common' everytime
# it starts up. The following condition not only checks that this pem file has been created, it also checks it
# is valid. Don't be caught out by the folder existing from a previous run.
echo -e "Making sure the CCF app frontend is up\n\t and the certs are fresh"

curl -s "$ccf_server/app/commit" --cacert "${ccf_cert_dir}/service_cert.pem" | jq .
status="$(curl -s"$ccf_server/app/commit" --cacert "${ccf_cert_dir}/service_cert.pem" $only_status_code)"
if [ "200" != $status ]; then
    echo -e "CCF app frontent end is not up...\n\try calling ./deploy_ccf.sh"
    exit 1
fi


# echo -e "Changing permissions on CCF user0 cert/private keys at \n\t${ccf_cert_dir}/user0_cert.pem \n\t${ccf_cert_dir}/user0_privk.pem"
# sudo chmod +r $ccf_cert_dir/user0_cert.pem $ccf_cert_dir/user0_privk.pem

# echo "Hardcoding certificates" #todo add to dockerfile
# python3 $PROJECT_ROOT/scripts/utils.py gen_ca_bundle "${ccf_cert_dir}/service_cert.pem" $PROJECT_ROOT/enclave/ca_bundle.h

echo "Building PVRA image"
docker-compose build $pvra_mode