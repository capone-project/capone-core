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

#include "lib/cfg.h"
#include "lib/log.h"

#include "keys.h"

int sd_sign_key_pair_from_config(struct sd_sign_key_pair *out, const struct cfg *cfg)
{
    uint8_t sign_pk[crypto_sign_PUBLICKEYBYTES],
            sign_sk[crypto_sign_SECRETKEYBYTES];
    char *value;

    value = cfg_get_str_value(cfg, "core", "public_key");
    if (value == NULL) {
        puts("Could not retrieve public key from config");
        goto out_err;
    }
    if (sodium_hex2bin(sign_pk, sizeof(sign_pk), value, strlen(value), NULL, NULL, NULL) < 0) {
        puts("Could not decode public key");
        goto out_err;
    }
    free(value);

    value = cfg_get_str_value(cfg, "core", "secret_key");
    if (value == NULL) {
        puts("Could not retrieve secret key from config");
        goto out_err;
    }
    if (sodium_hex2bin(sign_sk, sizeof(sign_sk), value, strlen(value), NULL, NULL, NULL)) {
        puts("Could not decode public key");
        goto out_err;
    }
    free(value);
    value = NULL;

    memcpy(out->pk.data, sign_pk, sizeof(sign_pk));
    memcpy(out->sk.data, sign_sk, sizeof(sign_sk));

    return 0;

out_err:
    free(value);

    return -1;
}

int sd_sign_key_pair_from_config_file(struct sd_sign_key_pair *out, const char *file)
{
    struct cfg cfg;
    int ret = 0;

    if (cfg_parse(&cfg, file) < 0) {
        ret = -1;
        goto out;
    }

    if (sd_sign_key_pair_from_config(out, &cfg) < 0) {
        ret = -1;
        goto out;
    }

out:
    cfg_free(&cfg);

    return ret;
}

int sd_sign_key_public_from_hex(struct sd_sign_key_public *out, const char *hex)
{
    int hexlen;

    hexlen = strlen(hex);
    if (hexlen != crypto_sign_PUBLICKEYBYTES * 2) {
        sd_log(LOG_LEVEL_ERROR, "Hex length does not match required public sign key length");
        return -1;
    }

    return sodium_hex2bin(out->data, sizeof(out->data), hex, hexlen, NULL, NULL, NULL);
}

int sd_sign_key_public_from_bin(struct sd_sign_key_public *out, const uint8_t *pk, size_t pklen)
{
    if (pklen != crypto_sign_PUBLICKEYBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Passed in buffer does not match required public sign key length");
        return -1;
    }

    memcpy(out->data, pk, sizeof(out->data));

    return 0;
}

int sd_sign_key_hex_from_bin(struct sd_sign_key_hex *out, const uint8_t *pk, size_t pklen)
{
    struct sd_sign_key_public key;

    if (sd_sign_key_public_from_bin(&key, pk, pklen) < 0)
        return -1;

    sd_sign_key_hex_from_key(out, &key);
    return 0;
}

void sd_sign_key_hex_from_key(struct sd_sign_key_hex *out, const struct sd_sign_key_public *key)
{
    sodium_bin2hex(out->data, sizeof(out->data), key->data, sizeof(key->data));
}

int sd_encrypt_key_pair_generate(struct sd_encrypt_key_pair *out)
{
    return crypto_box_keypair(out->pk.data, out->sk.data);
}

int sd_encrypt_key_public_from_bin(struct sd_encrypt_key_public *out, uint8_t *pk, size_t pklen)
{
    if (pklen != crypto_box_PUBLICKEYBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Passed in buffer does not match required public encrypt key length");
        return -1;
    }

    memcpy(out->data, pk, sizeof(out->data));

    return 0;
}

int sd_symmetric_key_generate(struct sd_symmetric_key *out)
{
    randombytes(out->data, sizeof(out->data));
    return 0;
}

int sd_symmetric_key_from_hex(struct sd_symmetric_key *out, const char *hex)
{
    int hexlen;

    hexlen = strlen(hex);
    if (hexlen != crypto_secretbox_KEYBYTES * 2) {
        sd_log(LOG_LEVEL_ERROR, "Hex length does not match required symmetric key length");
        return -1;
    }

    return sodium_hex2bin(out->data, sizeof(out->data), hex, hexlen, NULL, NULL, NULL);
}

int sd_symmetric_key_from_bin(struct sd_symmetric_key *out, const uint8_t *key, size_t keylen)
{
    if (keylen != crypto_secretbox_KEYBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Passed in buffer does not match required symmetric key length");
        return -1;
    }

    memcpy(out->data, key, sizeof(out->data));

    return 0;
}

int sd_symmetric_key_hex_from_bin(struct sd_symmetric_key_hex *out, const uint8_t *data, size_t datalen)
{
    struct sd_symmetric_key key;

    if (sd_symmetric_key_from_bin(&key, data, datalen) < 0)
        return -1;

    sd_symmetric_key_hex_from_key(out, &key);
    return 0;
}

void sd_symmetric_key_hex_from_key(struct sd_symmetric_key_hex *out, const struct sd_symmetric_key *key)
{
    sodium_bin2hex(out->data, sizeof(out->data), key->data, sizeof(key->data));
}
