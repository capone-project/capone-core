#!/bin/sh

set -x
set -e

doxygen -s scripts/Doxyfile

if test $# -eq 1 && test $1 = "publish"
then
    (
        PAGES="$(realpath ../gh-pages)"

        rm -rf "${PAGES}"
        git clone -b gh-pages . "${PAGES}"

        rm -rf "${PAGES}"/doxygen
        cp -r doxygen/html "${PAGES}"/doxygen

        cd "${PAGES}"

        if ! git diff --exit-code
        then
            return
        fi

        git add doxygen
        git commit --author='Travis <doxygen@travis>' -m 'Doxygen update'
    )
fi
