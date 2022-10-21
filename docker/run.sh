set -e

docker-compose  build enclave
docker-compose  run --rm enclave /bin/bash
