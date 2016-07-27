#!/bin/sh

set -e

cd build

CONTROLLER_KEY=d0c09c8cd02d960c285ee9d616d809d86024c27b915f8b1ee21a9b8c127f611c

CLIENT_CFG=scripts/config/client.conf
CLIENT_KEY=$(cat ${CLIENT_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')

CAP_CFG=scripts/config/server.conf
CAP_KEY=32798491bf871fbee6f4ea8e504a545d66e2bb14dde6404d910d0d3d90a20b35
CAP_KEY=$(cat ${CAP_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')
CAP_ADDR=localhost
CAP_PORT=1238

SERVICE_CFG=scripts/config/server.conf
SERVICE_KEY=$(cat ${SERVICE_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')
SERVICE_TYPE=exec
SERVICE_ADDR=192.168.178.38
SERVICE_PORT=1237
SERVICE_PARAMS="service-parameters=command=ls
                service-parameters=arg=-l
                service-parameters=arg=/"

CAP_SESSION="$(./cpn-client request \
    ${CLIENT_CFG} \
    ${CLIENT_KEY} \
    ${CAP_KEY} \
    ${CAP_ADDR} \
    ${CAP_PORT} \
    mode=request \
    invoker=${CLIENT_KEY} \
    requested-identity=${CONTROLLER_KEY} \
    service-identity=${SERVICE_KEY} \
    service-address=${SERVICE_ADDR} \
    service-port=${SERVICE_PORT} \
    ${SERVICE_PARAMS})"
CAP_ID="$(echo "$CAP_SESSION" | awk 'NR == 1 { print $2 }')"
CAP_SECRET="$(echo "$CAP_SESSION" | awk 'NR == 2 { print $2 }')"

SERVICE_SESSION="$(./cpn-client connect \
    ${CLIENT_CFG} \
    ${CAP_KEY} \
    ${CAP_ADDR} \
    ${CAP_PORT} \
    capabilities \
    ${CAP_ID} \
    ${CAP_SECRET} \
    request)"
SERVICE_ID="$(echo "$SERVICE_SESSION" | awk 'NR == 3 { print $2 }')"
SERVICE_SECRET="$(echo "$SERVICE_SESSION" | awk 'NR == 4 { print $2 }')"

./cpn-connect connect \
    ${CLIENT_CFG} \
    ${SERVICE_KEY} \
    ${SERVICE_ADDR} \
    ${SERVICE_PORT} \
    ${SERVICE_TYPE} \
    ${SERVICE_ID} \
    ${SERVICE_SECRET}
