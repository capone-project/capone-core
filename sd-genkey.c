/*
 * Copyright (C) 2016 Patrick Steinhardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>

#include <sodium.h>

#include "lib/common.h"

int main(int argc, char *argv[])
{
    unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES],
                  sk[crypto_sign_ed25519_SECRETKEYBYTES];
    char pkhex[sizeof(pk) * 2 + 1],
         skhex[sizeof(sk) * 2 + 1];

    if (argc > 1) {
        printf("USAGE: %s\n", argv[0]);
        return -1;
    }

    crypto_sign_ed25519_keypair(pk, sk);

    sodium_bin2hex(pkhex, sizeof(pkhex), pk, sizeof(pk));
    sodium_bin2hex(skhex, sizeof(skhex), sk, sizeof(sk));

    printf("Public key:\t%s\n"
           "Private key:\t%s\n",
           pkhex, skhex);

    return 0;
}
