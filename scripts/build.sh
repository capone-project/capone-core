#!/bin/sh

PREFIX="${HOME}/local"
export PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:${PREFIX}/lib/pkgconfig"

mkdir -p source/sd/build
cd source/sd/build
cmake -DCMAKE_INSTALL_PREFIX:PATH="${PREFIX}" ..
make
