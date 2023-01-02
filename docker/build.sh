#!/bin/bash
set -e
./build_ccf.sh
./deploy_ccf.sh
./build_pvra.sh