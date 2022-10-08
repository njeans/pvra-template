docker run --rm --name billboard -d --publish 8545:8545 trufflesuite/ganache-cli:latest --deterministic nerla --accounts $NUM_USERS --account_keys_path accounts.json --debug 
sleep 5
set -e
docker exec billboard cat accounts.json > accounts.json
