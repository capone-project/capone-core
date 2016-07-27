#!/bin/sh

set -e

sleep 2

sudo tc qdisc add dev lo root netem
trap 'sudo tc qdisc delete dev lo root netem' EXIT SIGINT

echo "latency,pkglen,delay"

for latency in 0 2 20
do
    sudo tc qdisc change dev lo root netem delay ${latency}ms

    Xvfb :1&
    Xvfb :2&

    sleep 3

    # Do an initial test without the cpn-server framework
    DISPLAY=:1 synergys --name server --no-daemon >/dev/null&
    SPID=$!
    sleep 1
    DISPLAY=:2 synergyc --name client --no-daemon 127.0.0.1 >/dev/null&
    CPID=$!
    sleep 1
    DELAY=$(./build/cpn-bench-input :1 :2 | awk '{ print $NF / 1000000 }')
    echo "$latency,0,$DELAY"

    killall -9 synergys synergyc Xvfb || true

    # Test delay with cpn-server and different block lengths
    for pkglen in 64 128 256 512 1024 1500 2048 4096
    do
        export CPN_BLOCKLEN=$pkglen

        sleep 5

        Xvfb :1&
        Xvfb :2&

        sleep 3

        DISPLAY=:2 ./build/cpn-server ./scripts/server.conf 2>&1 >/dev/null&
        SERVERPID=$!
        sleep 1

        SESSION=$(./build/cpn-client request \
            scripts/server.conf \
            32798491bf871fbee6f4ea8e504a545d66e2bb14dde6404d910d0d3d90a20b35 \
            32798491bf871fbee6f4ea8e504a545d66e2bb14dde6404d910d0d3d90a20b35 \
            127.0.0.1 \
            1236 | awk '{print $2}')
        DISPLAY=:1 ./build/cpn-client connect \
            scripts/server.conf \
            32798491bf871fbee6f4ea8e504a545d66e2bb14dde6404d910d0d3d90a20b35 \
            127.0.0.1 \
            1236 \
            synergy \
            ${SESSION} 2>&1 >/dev/null&
        CLIENTPID=$!

        sleep 5

        DELAY=$(./build/cpn-bench-input :1 :2 | awk '{ print $NF / 1000000 }')
        echo "$latency,$pkglen,$DELAY"

        killall -9 cpn-server cpn-client synergys synergyc Xvfb || true
    done
done
