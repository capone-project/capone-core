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

int main(int argc, char *argv[])
{
    struct cpn_sign_key_pair keys;
    char pkhex[sizeof(keys.pk.data) * 2 + 1],
         skhex[sizeof(keys.sk.data) * 2 + 1];

    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts("sd-genkey " VERSION "\n"
             "Copyright (C) 2016 Patrick Steinhardt\n"
             "License GPLv3: GNU GPL version 3 <http://gnu.org/licenses/gpl.html>.\n"
             "This is free software; you are free to change and redistribute it.\n"
             "There is NO WARRANTY, to the extent permitted by the law.");
        return 0;
    }

    if (argc > 1) {
        printf("USAGE: %s\n", argv[0]);
        return -1;
    }

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
