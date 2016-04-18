#!/bin/sh

set -x
set -e

# install protobuf
(
    cd /tmp
    wget https://github.com/google/protobuf/releases/download/v2.5.0/protobuf-2.5.0.tar.bz2
    tar -xvf protobuf-2.5.0.tar.bz2
    cd protobuf-2.5.0
    ./configure --prefix=/usr
    make
    sudo make install
)

# install protobuf-c
(
    cd /tmp
    wget https://github.com/protobuf-c/protobuf-c/releases/download/v1.0.2/protobuf-c-1.0.2.tar.gz
    tar -xvf protobuf-c-1.0.2.tar.gz
    cd protobuf-c-1.0.2
    ./configure --prefix=/usr
    make
    sudo make install
)

# install cmocka
(
    cd /tmp
    wget https://cmocka.org/files/1.0/cmocka-1.0.1.tar.xz
    tar -xvf cmocka-1.0.1.tar.xz
    cd cmocka-1.0.1
    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ..
    make
    sudo make install
)

# install libsodium-1.0.8
(
    cd /tmp
    wget https://github.com/jedisct1/libsodium/releases/download/1.0.8/libsodium-1.0.8.tar.gz
    tar -xvf libsodium-1.0.8.tar.gz
    cd libsodium-1.0.8
    ./configure --prefix=/usr
    make
    sudo make install
)
