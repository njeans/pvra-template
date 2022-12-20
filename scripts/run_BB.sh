NUM_ACCOUNTS=$((NUM_USERS + 1))
docker run --rm --name billboard -d --publish 8545:8545 trufflesuite/ganache-cli:latest --deterministic nerla --accounts $NUM_ACCOUNTS --account_keys_path accounts.json --debug
export BILLBOARD_URL="http://$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' billboard):8545"
echo "BILLBOARD_URL=$BILLBOARD_URL"
sleep 5
set -e
docker exec billboard cat accounts.json > $PROJECT_ROOT/accounts/accounts.json