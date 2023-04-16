#!/bin/bash
set -e
if [ "$CCF_ENABLE" = "1" ]; then
    ./deploy_ccf.sh
fi
./deploy_pvra.sh