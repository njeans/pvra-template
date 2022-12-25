#!/bin/bash
set -e
./deploy_ccf.sh
./run_pvra.sh $@
