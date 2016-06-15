#!/bin/sh

set -e

Xvfb :1&
trap "kill -9 $!" EXIT
Xvfb :2&
trap "kill -9 $!" EXIT

sleep 2

sudo tc qdisc add dev lo root netem
trap 'sudo tc qdisc delete dev lo root netem' EXIT

echo "latency,pkglen,delay"

for latency in 0 2 20
do
    sudo tc qdisc change dev lo root netem delay ${latency}ms

    # Do an initial test without the sd-server framework
    DISPLAY=:1 synergys --name server --no-daemon >/dev/null&
    SPID=$!
    sleep 1
    DISPLAY=:2 synergyc --name client --no-daemon 127.0.0.1 >/dev/null&
    CPID=$!
    sleep 1
    DELAY=$(./source/sd/build/sd-bench-input :1 :2 | awk '{ sum += $NF } END { print sum / NR }')
    echo "$latency,0,$DELAY"

    kill -9 $SPID $CPID

    # Test delay with sd-server and different block lengths
    for pkglen in 64 128 256 512 1024 1500 2048 4096
    do
        export SD_BLOCKLEN=$pkglen

        DISPLAY=:2 ./source/sd/build/sd-server ./scripts/server.conf 2>&1 >/dev/null&
        SERVERPID=$!
        sleep 1

        SESSION=$(./source/sd/build/sd-connect request \
            scripts/server.conf \
            32798491bf871fbee6f4ea8e504a545d66e2bb14dde6404d910d0d3d90a20b35 \
            32798491bf871fbee6f4ea8e504a545d66e2bb14dde6404d910d0d3d90a20b35 \
            127.0.0.1 \
            1236 | awk '{print $2}')
        DISPLAY=:1 ./source/sd/build/sd-connect connect \
            scripts/server.conf \
            32798491bf871fbee6f4ea8e504a545d66e2bb14dde6404d910d0d3d90a20b35 \
            127.0.0.1 \
            1236 \
            synergy \
            ${SESSION} 2>&1 >/dev/null&
        CLIENTPID=$!

        sleep 5

        DELAY=$(./source/sd/build/sd-bench-input :1 :2 | awk '{ sum += $NF } END { print sum / NR }')
        echo "$latency,$pkglen,$DELAY"

        kill $SERVERPID $CLIENTPID >/dev/null
        pkill synergys
        sleep 2
    done
done
