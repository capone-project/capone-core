#!/bin/sh

set -e

cd source/sd/build

CLIENT_CFG=../config/client.conf
CLIENT_KEY=$(cat ${CLIENT_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')

INVOKER_CFG=../config/server.conf
INVOKER_KEY=$(cat ${INVOKER_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')
INVOKER_ADDR=192.168.0.100
INVOKER_PORT=1239

SERVICE_CFG=../config/server.conf
SERVICE_KEY=$(cat ${SERVICE_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')
SERVICE_TYPE=exec
SERVICE_ADDR=192.168.0.100
SERVICE_PORT=1237
SERVICE_ARGS="command=ls
              arg=-l"

SERVICE_SESSION=$(./sd-connect request \
    ${CLIENT_CFG} \
    ${INVOKER_KEY} \
    ${SERVICE_KEY} \
    ${SERVICE_ADDR} \
    ${SERVICE_PORT} \
    ${SERVICE_ARGS} | awk '{print $2}')

INVOKE_SESSION=$(./sd-connect request \
    ${CLIENT_CFG} \
    ${CLIENT_KEY} \
    ${INVOKER_KEY} \
    ${INVOKER_ADDR} \
    ${INVOKER_PORT} \
    service-identity=${SERVICE_KEY} \
    service-address=${SERVICE_ADDR} \
    service-port=${SERVICE_PORT} \
    service-type=${SERVICE_TYPE} \
    sessionid=${SERVICE_SESSION} | awk '{print $2}')

./sd-connect connect \
    ${CLIENT_CFG} \
    ${INVOKER_KEY} \
    ${INVOKER_ADDR} \
    ${INVOKER_PORT} \
    invoke \
    ${INVOKE_SESSION}
