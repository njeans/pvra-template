#!/bin/bash
set -e
docker-compose down --remove-orphans
./build.sh
./deploy_ccf.sh
./deploy_pvra.sh