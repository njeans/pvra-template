#!/bin/bash
set -e
if [[ -z "${PROJECT_ROOT}" ]];
then
  echo "Error: environment variable PROJECT_ROOT not set."
  exit 1
fi
if [ "$CCF_ENABLE" = "1" ]; then
  ccf_server=https://localhost:8546
  ccf_cert_dir=$PROJECT_ROOT/shared/ccf_sandbox
  only_status_code="-s -o /dev/null -w %{http_code}"
  sudo chown -R $USER $ccf_cert_dir/user0*
  sudo chown -R $USER $ccf_cert_dir/member0*
  set +e
  status="$(curl -s "$ccf_server/app/commit" --cacert "${ccf_cert_dir}/service_cert.pem" $only_status_code)"
  set -e
  if [ "200" != $status ]; then
      curl -s "$ccf_server/app/commit" --cacert "${ccf_cert_dir}/service_cert.pem" | jq .
      echo -e "CCF app frontent end is not up...\ntry calling ./build_ccf.sh and ./deploy_ccf.sh"
      exit 1
  fi
else
  COMPOSE_FILE="-f $PROJECT_ROOT/docker/docker-compose-no-ccf.yml"
fi
if [ "$SGX_MODE" = "SW" ]; then
  echo "Running in Simulation mode"
  docker-compose $COMPOSE_FILE run --rm enclave-sim $@
else
  echo "Running in Hardware mode"
  docker-compose $COMPOSE_FILE run --rm enclave $@
fi
