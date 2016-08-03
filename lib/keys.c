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

#include "capone/cfg.h"
#include "capone/log.h"
#include "capone/keys.h"

#define HEXCHARS "1234567890abcdefABCDEF"

static int verify_hex(const char *hex)
{
    const char *c;
    int ret = 0;

    for (c = hex; *c != '\0'; c++) {
        if (memchr(HEXCHARS, *c, strlen(HEXCHARS)) == NULL)
            ret |= 1;
        else
            ret |= 0;
    }

    return -ret;
}

static int cpn_sign_key_secret_from_hex(struct cpn_sign_key_secret *out, const char *hex)
{
    int hexlen;

    if (out == NULL || hex == NULL) {
        cpn_log(LOG_LEVEL_ERROR, "Got no secret keys to decipher");
        return -1;
    }

    if (verify_hex(hex) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Got secret key with invalid characters");
        return -1;
    }

    hexlen = strlen(hex);
    if (hexlen != crypto_sign_SECRETKEYBYTES * 2) {
        cpn_log(LOG_LEVEL_ERROR, "Hex length does not match required secret sign key length");
        return -1;
    }

    return sodium_hex2bin(out->data, sizeof(out->data), hex, hexlen, NULL, NULL, NULL);
}

int cpn_sign_key_pair_generate(struct cpn_sign_key_pair *out)
{
    return crypto_sign_ed25519_keypair(out->pk.data, out->sk.data);
}

int cpn_sign_key_pair_from_config(struct cpn_sign_key_pair *out, const struct cpn_cfg *cfg)
{
    struct cpn_sign_key_public pk;
    struct cpn_sign_key_secret sk;
    char *value;

    value = cpn_cfg_get_str_value(cfg, "core", "public_key");
    if (cpn_sign_key_public_from_hex(&pk, value) < 0) {
        goto out_err;
    }
    free(value);

    value = cpn_cfg_get_str_value(cfg, "core", "secret_key");
    if (cpn_sign_key_secret_from_hex(&sk, value) < 0) {
        goto out_err;
    }
    free(value);
    value = NULL;

    memcpy(&out->pk, &pk, sizeof(pk));
    memcpy(&out->sk, &sk, sizeof(sk));

    return 0;

out_err:
    free(value);

    return -1;
}

int cpn_sign_key_pair_from_config_file(struct cpn_sign_key_pair *out, const char *file)
{
    struct cpn_cfg cfg;
    int ret = 0;

    memset(&cfg, 0, sizeof(cfg));

    if (cpn_cfg_parse(&cfg, file) < 0) {
        ret = -1;
        goto out;
    }

    if (cpn_sign_key_pair_from_config(out, &cfg) < 0) {
        ret = -1;
        goto out;
    }

out:
    cpn_cfg_free(&cfg);

    return ret;
}

int cpn_sign_key_public_from_hex(struct cpn_sign_key_public *out, const char *hex)
{
    int hexlen;

    if (out == NULL || hex == NULL) {
        cpn_log(LOG_LEVEL_ERROR, "Got no keys to decipher");
        return -1;
    }

    if (verify_hex(hex) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Got public key with invalid characters");
        return -1;
    }

    hexlen = strlen(hex);
    if (hexlen != crypto_sign_PUBLICKEYBYTES * 2) {
        cpn_log(LOG_LEVEL_ERROR, "Hex length does not match required public sign key length");
        return -1;
    }

    return sodium_hex2bin(out->data, sizeof(out->data), hex, hexlen, NULL, NULL, NULL);
}

int cpn_sign_key_public_from_bin(struct cpn_sign_key_public *out, const uint8_t *pk, size_t pklen)
{
    if (pklen != crypto_sign_PUBLICKEYBYTES) {
        cpn_log(LOG_LEVEL_ERROR, "Passed in buffer does not match required public sign key length");
        return -1;
    }

    memcpy(out->data, pk, sizeof(out->data));

    return 0;
}

int cpn_sign_key_hex_from_bin(struct cpn_sign_key_hex *out, const uint8_t *pk, size_t pklen)
{
    struct cpn_sign_key_public key;

    if (cpn_sign_key_public_from_bin(&key, pk, pklen) < 0)
        return -1;

    cpn_sign_key_hex_from_key(out, &key);
    return 0;
}

void cpn_sign_key_hex_from_key(struct cpn_sign_key_hex *out, const struct cpn_sign_key_public *key)
{
    sodium_bin2hex(out->data, sizeof(out->data), key->data, sizeof(key->data));
}

int cpn_encrypt_key_pair_generate(struct cpn_encrypt_key_pair *out)
{
    return crypto_box_keypair(out->pk.data, out->sk.data);
}

int cpn_encrypt_key_public_from_bin(struct cpn_encrypt_key_public *out, uint8_t *pk, size_t pklen)
{
    if (pklen != crypto_box_PUBLICKEYBYTES) {
        cpn_log(LOG_LEVEL_ERROR, "Passed in buffer does not match required public encrypt key length");
        return -1;
    }

    memcpy(out->data, pk, sizeof(out->data));

    return 0;
}

int cpn_symmetric_key_generate(struct cpn_symmetric_key *out)
{
    randombytes(out->data, sizeof(out->data));
    return 0;
}

int cpn_symmetric_key_from_hex(struct cpn_symmetric_key *out, const char *hex)
{
    int hexlen;

    hexlen = strlen(hex);
    if (hexlen != crypto_secretbox_KEYBYTES * 2) {
        cpn_log(LOG_LEVEL_ERROR, "Hex length does not match required symmetric key length");
        return -1;
    }

    return sodium_hex2bin(out->data, sizeof(out->data), hex, hexlen, NULL, NULL, NULL);
}

int cpn_symmetric_key_from_bin(struct cpn_symmetric_key *out, const uint8_t *key, size_t keylen)
{
    if (keylen != crypto_secretbox_KEYBYTES) {
        cpn_log(LOG_LEVEL_ERROR, "Passed in buffer does not match required symmetric key length");
        return -1;
    }

    memcpy(out->data, key, sizeof(out->data));

    return 0;
}

int cpn_symmetric_key_hex_from_bin(struct cpn_symmetric_key_hex *out, const uint8_t *data, size_t datalen)
{
    struct cpn_symmetric_key key;

    if (cpn_symmetric_key_from_bin(&key, data, datalen) < 0)
        return -1;

    cpn_symmetric_key_hex_from_key(out, &key);
    return 0;
}

void cpn_symmetric_key_hex_from_key(struct cpn_symmetric_key_hex *out, const struct cpn_symmetric_key *key)
{
    sodium_bin2hex(out->data, sizeof(out->data), key->data, sizeof(key->data));
}
