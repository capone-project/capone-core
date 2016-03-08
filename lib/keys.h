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

#ifndef SD_LIB_KEYS_H
#define SD_LIB_KEYS_H

#include <sodium.h>

struct sd_sign_key_secret {
    uint8_t data[crypto_sign_SECRETKEYBYTES];
};
struct sd_sign_key_public {
    uint8_t data[crypto_sign_PUBLICKEYBYTES];
};
struct sd_sign_key_pair {
    struct sd_sign_key_secret sk;
    struct sd_sign_key_public pk;
};

struct sd_encrypt_key_secret {
    uint8_t data[crypto_box_SECRETKEYBYTES];
};
struct sd_encrypt_key_public {
    uint8_t data[crypto_box_PUBLICKEYBYTES];
};
struct sd_encrypt_key_pair {
    struct sd_encrypt_key_secret sk;
    struct sd_encrypt_key_public pk;
};

struct sd_symmetric_key {
    uint8_t data[crypto_secretbox_KEYBYTES];
};

int sd_sign_key_pair_from_config_file(struct sd_sign_key_pair *out, const char *file);
int sd_sign_key_public_from_hex(struct sd_sign_key_public *out, const char *hex);
int sd_sign_key_public_from_bin(struct sd_sign_key_public *out,
        uint8_t *pk, size_t pklen);

int sd_encrypt_key_pair_generate(struct sd_encrypt_key_pair *out);
int sd_encrypt_key_public_from_bin(struct sd_encrypt_key_public *out,
        uint8_t *pk, size_t pklen);

int sd_symmetric_key_generate(struct sd_symmetric_key *out);
int sd_symmetric_key_from_hex(struct sd_symmetric_key *out, const char *hex);

#endif
