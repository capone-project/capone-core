#!/bin/sh

set -e

tc qdisc add dev lo root netem
trap 'tc qdisc delete dev lo root netem' EXIT

echo "latency,pkglen,connect,await"

for latency in 0 2 20
do
    tc qdisc change dev lo root netem delay ${latency}ms

    for pkglen in 64 128 256 512 1024 1500 2048 4096
    do
        RESULT=$(./build/cpn-bench-latency -l ${pkglen})
        CONNECT=$(echo "${RESULT}" | head -n1 | awk '{print $3 / 1000000}')
        AWAIT=$(echo "${RESULT}" | tail -n1 | awk '{print $3 / 1000000}')

        echo "${latency},${pkglen},${CONNECT},${AWAIT}"
    done
done

