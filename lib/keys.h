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

#include <sodium.h>

struct sd_keys_secret {
    uint8_t sign[crypto_sign_ed25519_SECRETKEYBYTES];
    uint8_t box[crypto_scalarmult_curve25519_BYTES];
};

struct sd_keys_public {
    uint8_t sign[crypto_sign_ed25519_PUBLICKEYBYTES];
    uint8_t box[crypto_scalarmult_curve25519_BYTES];
};

struct sd_keys {
    struct sd_keys_secret sk;
    struct sd_keys_public pk;
};

int sd_keys_from_config_file(struct sd_keys *out, const char *file);
int sd_keys_public_from_hex(struct sd_keys_public *out, const char *hex);
int sd_keys_public_from_bin(struct sd_keys_public *out, uint8_t *data, size_t len);
