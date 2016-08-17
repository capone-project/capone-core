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

#include <string.h>
#include <stdio.h>

#include <sodium.h>

#include "capone/common.h"
#include "capone/keys.h"
#include "capone/opts.h"

int main(int argc, const char *argv[])
{
    struct cpn_sign_key_pair keys;
    char pkhex[sizeof(keys.pk.data) * 2 + 1],
         skhex[sizeof(keys.sk.data) * 2 + 1];

    if (cpn_opts_parse_cmd(NULL, argc, argv) < 0)
        return -1;

    if (cpn_sign_key_pair_generate(&keys) < 0) {
        puts("Error generating key pair");
        return -1;
    }

    sodium_bin2hex(pkhex, sizeof(pkhex), keys.pk.data, sizeof(keys.pk.data));
    sodium_bin2hex(skhex, sizeof(skhex), keys.sk.data, sizeof(keys.sk.data));

    printf("Public key:\t%s\n"
           "Private key:\t%s\n",
           pkhex, skhex);

    return 0;
}
