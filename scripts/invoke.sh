#!/bin/sh

set -e

cd build

CLIENT_CFG=../scripts/config/client.conf

INVOKER_CFG=../scripts/config/server.conf
INVOKER_KEY=$(cat ${INVOKER_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')
INVOKER_ADDR=127.0.0.1
INVOKER_PORT=1239

SERVICE_CFG=../scripts/config/server.conf
SERVICE_KEY=$(cat ${SERVICE_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')
SERVICE_TYPE=exec
SERVICE_ADDR=127.0.0.1
SERVICE_PORT=1237
SERVICE_ARGS="--command ls --arguments -l"

SERVICE_SESSION=$(./cpn-client \
    --config ${CLIENT_CFG} \
    --remote-key ${SERVICE_KEY} \
    --remote-host ${SERVICE_ADDR} \
    --remote-port ${SERVICE_PORT} \
    request \
    --service-type ${SERVICE_TYPE} \
    --parameters ${SERVICE_ARGS})
SERVICE_ID="$(echo "$SERVICE_SESSION" | awk 'NR == 1 { print $2 }')"
SERVICE_SECRET="$(echo "$SERVICE_SESSION" | awk 'NR == 2 { print $2 }')"

CAP=$(./cpn-derive -c "$SERVICE_SECRET" -i "$INVOKER_KEY" -r "x")

INVOKE_SESSION=$(./cpn-client \
    --config ${CLIENT_CFG} \
    --remote-key ${INVOKER_KEY} \
    --remote-host ${INVOKER_ADDR} \
    --remote-port ${INVOKER_PORT} \
    request \
    --service-type invoke \
    --parameters \
    --service-identity ${SERVICE_KEY} \
    --service-address ${SERVICE_ADDR} \
    --service-port ${SERVICE_PORT} \
    --service-type ${SERVICE_TYPE} \
    --sessionid ${SERVICE_ID} \
    --capability ${CAP})
INVOKE_ID="$(echo "$INVOKE_SESSION" | awk 'NR == 1 { print $2 }')"
INVOKE_SECRET="$(echo "$INVOKE_SESSION" | awk 'NR == 2 { print $2 }')"

./cpn-client \
    --config ${CLIENT_CFG} \
    --remote-key ${INVOKER_KEY} \
    --remote-host ${INVOKER_ADDR} \
    --remote-port ${INVOKER_PORT} \
    connect \
    --service-type invoke \
    --session-id ${INVOKE_ID} \
    --session-cap ${INVOKE_SECRET}
