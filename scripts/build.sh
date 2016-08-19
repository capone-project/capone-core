#!/bin/sh

set -x
set -e

PREFIX="${HOME}/local"

export PATH="${PATH}:${PREFIX}/bin"
export PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:${PREFIX}/lib/pkgconfig"

if test -n "${APPVEYOR_BUILD_FOLDER}"
then
    cd "${APPVEYOR_BUILD_FOLDER}"
elif test -n "${TRAVIS_BUILD_DIR}"
then
    cd "${TRAVIS_BUILD_DIR}"
fi

git submodule update --init

mkdir -p build
cd build
cmake -G "${GENERATOR}" -DCMAKE_INSTALL_PREFIX:PATH="${PREFIX}" ..
make
