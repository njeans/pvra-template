#!/bin/bash
docker-compose down --remove-orphans
docker volume rm pvra_accounts pvra_aesmd-socket 
docker volume rm pvra_ccf_sandbox 
docker volume rm pvra_ccf_workspace 
docker volume rm pvra_ccf_workspace_sgx 
sudo rm -rf $PROJECT_ROOT/shared/*
docker network rm pvra_default


