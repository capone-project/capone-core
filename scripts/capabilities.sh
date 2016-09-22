#!/bin/sh

set -e

cd build

CONTROLLER_KEY=d0c09c8cd02d960c285ee9d616d809d86024c27b915f8b1ee21a9b8c127f611c

CLIENT_CFG=../scripts/config/client.conf
CLIENT_KEY=$(cat ${CLIENT_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')

CAP_CFG=../scripts/config/server.conf
CAP_KEY=$(cat ${CAP_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')
CAP_ADDR=127.0.0.1
CAP_PORT=1238

SERVICE_CFG=../scripts/config/server.conf
SERVICE_KEY=$(cat ${SERVICE_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')
SERVICE_TYPE=exec
SERVICE_ADDR=192.168.0.100
SERVICE_PORT=1237
SERVICE_PARAMS="--command ls --arguments -l"

CAP_SESSION=$(./cpn-client \
    --config ${CLIENT_CFG} \
    --remote-key ${CAP_KEY} \
    --remote-host ${CAP_ADDR} \
    --remote-port ${CAP_PORT} \
    request \
    --service-type capabilities \
    --parameters \
    request \
    --requested-identity "$CONTROLLER_KEY" \
    --service-identity "$SERVICE_KEY" \
    --service-address "$SERVICE_ADDR" \
    --service-port "$SERVICE_PORT" \
    --service-type "$SERVICE_TYPE" \
    --service-parameters ${SERVICE_PARAMS})
CAP_ID="$(echo "$CAP_SESSION" | awk 'NR == 1 { print $2 }')"
CAP_SECRET="$(echo "$CAP_SESSION" | awk 'NR == 2 { print $2 }')"

SERVICE_SESSION="$(./cpn-client \
    --config ${CLIENT_CFG} \
    --remote-key ${CAP_KEY} \
    --remote-host ${CAP_ADDR} \
    --remote-port ${CAP_PORT} \
    connect \
    --service-type capabilities \
    --session-id ${CAP_ID} \
    --session-cap ${CAP_SECRET})"
SERVICE_ID="$(echo "$SERVICE_SESSION" | awk 'NR == 2 { print $2 }')"
SERVICE_SECRET="$(echo "$SERVICE_SESSION" | awk 'NR == 3 { print $2 }')"

./cpn-client \
    --config ${CLIENT_CFG} \
    --remote-key ${SERVICE_KEY} \
    --remote-host ${SERVICE_ADDR} \
    --remote-port ${SERVICE_PORT} \
    connect \
    --service-type ${SERVICE_TYPE} \
    --session-id ${SERVICE_ID} \
    --session-cap ${SERVICE_SECRET}
