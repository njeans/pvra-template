#!/bin/bash
set -e
if [ "$CCF_ENABLE" = "1" ]; then
    ./build_ccf.sh
    ./deploy_ccf.sh
fi
./build_pvra.sh