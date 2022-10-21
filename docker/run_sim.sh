set -e
export APP_NAME=sdt

docker-compose -f docker-compose-sim.yml build enclave
docker-compose -f docker-compose-sim.yml run --rm enclave /bin/bash
