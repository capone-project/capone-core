#!/bin/sh

set -e

cd source/sd/build

CONTROLLER_KEY=f67b81a00b5be62a983295a083116e77ed7293be1813a379ce2fc0d52512abed

CLIENT_CFG=../config/client.conf
CLIENT_KEY=$(cat ${CLIENT_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')

CAP_CFG=../config/server.conf
CAP_KEY=32798491bf871fbee6f4ea8e504a545d66e2bb14dde6404d910d0d3d90a20b35
CAP_KEY=$(cat ${CAP_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')
CAP_ADDR=localhost
CAP_PORT=1238

SERVICE_CFG=../config/server.conf
SERVICE_KEY=$(cat ${SERVICE_CFG} | sed -n 's/^public_key=\(.*\)$/\1/p')
SERVICE_TYPE=exec
SERVICE_ADDR=192.168.0.100
SERVICE_PORT=1237
SERVICE_PARAMS="service-parameters=command=ls
                service-parameters=arg=-l
                service-parameters=arg=/"

CAP_SESSION=$(./sd-connect request \
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
    ${SERVICE_PARAMS} | awk '{print $2}')

SERVICE_SESSION=$(./sd-connect connect \
    ${CLIENT_CFG} \
    ${CAP_KEY} \
    ${CAP_ADDR} \
    ${CAP_PORT} \
    capabilities \
    ${CAP_SESSION} \
    request | tail -n1 | awk '{print $2}')

./sd-connect connect \
    ${CLIENT_CFG} \
    ${SERVICE_KEY} \
    ${SERVICE_ADDR} \
    ${SERVICE_PORT} \
    ${SERVICE_TYPE} \
    ${SERVICE_SESSION}
