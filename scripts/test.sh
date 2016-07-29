#!/bin/sh

set -x
set -e

if test -n "${APPVEYOR_BUILD_FOLDER}"
then
    cd "${APPVEYOR_BUILD_FOLDER}"
elif test -n "${TRAVIS_BUILD_DIR}"
then
    cd "${TRAVIS_BUILD_DIR}"
fi

PREFIX="${HOME}/local"

export PATH="${PATH}:${PREFIX}/bin:${PWD}/build"

build/test/cpn-test --verbose
