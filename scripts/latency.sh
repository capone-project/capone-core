#!/bin/sh

set -e

(
    cd source/sd
    rm -rf build
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make
) 2>&1 1>/dev/null

sudo tc qdisc delete dev lo root netem || true
sudo tc qdisc add dev lo root netem

echo "latency,connect,await"

for latency in 0 2 20 25 50 100
do
    sudo tc qdisc change dev lo root netem delay ${latency}ms

    (
        cd source/sd/build
        make 2>&1 1>/dev/null
    )

    RESULT=$(./source/sd/build/sd-latency | awk '!(NR%2) {printf "%s,%s", $NF, p} {p=$NF}')
    CONNECT=$(echo "${RESULT}" | cut -d ',' -f 1)
    CONNECT=$(echo "scale=3; ${CONNECT} / 1000 / 1000" | bc)
    AWAIT=$(echo "${RESULT}" | cut -d ',' -f 2)
    AWAIT=$(echo "scale=3; ${AWAIT} / 1000 / 1000" | bc)

    echo "${latency},${CONNECT},${AWAIT}"
done

sudo tc qdisc delete dev lo root netem
