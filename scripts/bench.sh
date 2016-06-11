#!/bin/sh

set -e

echo "datalen,pkglen,wxplain,rxplain,tpplain,wxenc,rxenc,tpenc"

for datalen in 256 1024 102400 10240000
do
    for pkglen in 64 128 256 512 1024 1500 2048 4096
    do
        PLAIN=$(./source/sd/build/sd-bench --plain ${datalen} ${pkglen} | awk '!(NR%2) {printf "%s %s", $NF, p} {p=$NF}')
        PLAIN_WX=$(echo "$PLAIN" | cut -d ' ' -f 1)
        PLAIN_RX=$(echo "$PLAIN" | cut -d ' ' -f 2)
        PLAIN_TP=$(echo "scale=3; ($datalen / $PLAIN_RX) * 1000000000 / 1024 / 1024" | bc -l)

        ENCRYPTED=$(./source/sd/build/sd-bench --encrypted ${datalen} ${pkglen} | awk '!(NR%2) {printf "%s %s", $NF, p} {p=$NF}')
        ENCRYPTED_WX=$(echo "$ENCRYPTED" | cut -d ' ' -f 1)
        ENCRYPTED_RX=$(echo "$ENCRYPTED" | cut -d ' ' -f 2)
        ENCRYPTED_TP=$(echo "scale=3; ($datalen / $ENCRYPTED_RX) * 1000000000 / 1024 / 1024" | bc -l)

        echo "${datalen},${pkglen},${PLAIN_WX},${PLAIN_RX},${PLAIN_TP},${ENCRYPTED_WX},${ENCRYPTED_RX},${ENCRYPTED_TP}"
    done
done
