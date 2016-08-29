#!/bin/sh

set -x
set -e

PREFIX="${HOME}/local"

export PATH="${PATH}:${PREFIX}/bin"
export PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:${PREFIX}/lib/pkgconfig"

if test -d "${PREFIX}" -a -n "$(ls -A ${PREFIX}/)"
then
    echo "Using cached dependencies"
    exit
fi

# install protobuf
(
    cd /tmp
    wget https://github.com/google/protobuf/archive/v3.0.0.tar.gz
    tar -xf v3.0.0.tar.gz
    cd protobuf-3.0.0
    mkdir build-dir
    cd build-dir
    cmake -G "${GENERATOR}" \
        -DCMAKE_INSTALL_PREFIX:PATH="${PREFIX}" \
        -Dprotobuf_BUILD_TESTS=OFF \
        -Dprotobuf_WITH_ZLIB=OFF \
        ../cmake
    make
    make install
)

# install protobuf-c
(
    cd /tmp
    wget https://github.com/protobuf-c/protobuf-c/releases/download/v1.0.2/protobuf-c-1.0.2.tar.gz
    tar -xf protobuf-c-1.0.2.tar.gz
    cd protobuf-c-1.0.2
    mkdir build
    cd build
    cmake -G "${GENERATOR}" \
        -DCMAKE_INSTALL_PREFIX:PATH="${PREFIX}" \
        ../build-cmake
    make
    make install
)

# install cmocka
(
    cd /tmp
    wget https://cmocka.org/files/1.0/cmocka-1.0.1.tar.xz
    tar -xf cmocka-1.0.1.tar.xz
    cd cmocka-1.0.1
    mkdir build
    cd build
    # Fix building without RPATH
    cmake -G "${GENERATOR}" \
        -DCMAKE_MACOSX_RPATH=ON \
        -DCMAKE_INSTALL_PREFIX:PATH="${PREFIX}" \
        ..
    make
    make install
)

# install libsodium-1.0.8
(
    cd /tmp
    wget https://github.com/jedisct1/libsodium/releases/download/1.0.8/libsodium-1.0.8.tar.gz
    tar -xf libsodium-1.0.8.tar.gz
    cd libsodium-1.0.8
    autoreconf -fi
    ./configure --host="${TARGET}" --prefix="${PREFIX}"
    make
    make install
)
