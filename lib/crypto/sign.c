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

#include <sodium/crypto_sign.h>
#include <sodium/utils.h>

#include "capone/common.h"
#include "capone/log.h"
#include "capone/crypto/sign.h"

int cpn_sign_keys_generate(struct cpn_sign_keys *out)
{
    return crypto_sign_ed25519_keypair(out->pk.data, out->sk.data);
}

int cpn_sign_pk_from_bin(struct cpn_sign_pk *out, const uint8_t *pk, size_t pklen)
{
    if (pklen != crypto_sign_PUBLICKEYBYTES) {
        cpn_log(LOG_LEVEL_ERROR, "Passed in buffer does not match required public sign key length");
        return -1;
    }

    memcpy(out->data, pk, sizeof(out->data));

    return 0;
}

int cpn_sign_pk_from_hex(struct cpn_sign_pk *out, const char *hex)
{
    if (hex == NULL) {
        cpn_log(LOG_LEVEL_ERROR, "Error parsing nonexistent public signature key");
        return -1;
    }

    if (parse_hex(out->data, sizeof(out->data), hex, strlen(hex)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Error parsing invalid public signature key");
        return -1;
    }
    return 0;
}

int cpn_sign_pk_from_proto(struct cpn_sign_pk *out, const IdentityMessage *msg)
{
    if (msg->data.len != sizeof(out->data))
        return -1;
    memcpy(out->data, msg->data.data, msg->data.len);
    return 0;
}

int cpn_sign_pk_to_proto(IdentityMessage **out, const struct cpn_sign_pk *key)
{
    IdentityMessage *result = malloc(sizeof(IdentityMessage));
    identity_message__init(result);

    result->data.len = sizeof(key->data);
    result->data.data = malloc(sizeof(key->data));
    memcpy(result->data.data, key->data, sizeof(key->data));

    *out = result;

    return 0;
}

int cpn_sign_pk_hex_from_bin(struct cpn_sign_pk_hex *out, const uint8_t *pk, size_t pklen)
{
    struct cpn_sign_pk key;

    if (cpn_sign_pk_from_bin(&key, pk, pklen) < 0)
        return -1;

    cpn_sign_pk_hex_from_key(out, &key);
    return 0;
}

void cpn_sign_pk_hex_from_key(struct cpn_sign_pk_hex *out, const struct cpn_sign_pk *key)
{
    sodium_bin2hex(out->data, sizeof(out->data), key->data, sizeof(key->data));
}

static int cpn_sign_sk_from_hex(struct cpn_sign_sk *out, const char *hex)
{
    if (hex == NULL) {
        cpn_log(LOG_LEVEL_ERROR, "Error parsing nonexistent secret signature key");
        return -1;
    }

    if (parse_hex(out->data, sizeof(out->data), hex, strlen(hex)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Error parsing invalid secret signature key");
        return -1;
    }
    return 0;
}

int cpn_sign_keys_from_config(struct cpn_sign_keys *out, const struct cpn_cfg *cfg)
{
    struct cpn_sign_pk pk;
    struct cpn_sign_sk sk;
    char *value;

    value = cpn_cfg_get_str_value(cfg, "core", "public_key");
    if (cpn_sign_pk_from_hex(&pk, value) < 0) {
        goto out_err;
    }
    free(value);

    value = cpn_cfg_get_str_value(cfg, "core", "secret_key");
    if (cpn_sign_sk_from_hex(&sk, value) < 0) {
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

int cpn_sign_keys_from_config_file(struct cpn_sign_keys *out, const char *file)
{
    struct cpn_cfg cfg;
    int ret = 0;

    memset(&cfg, 0, sizeof(cfg));

    if (cpn_cfg_parse(&cfg, file) < 0) {
        ret = -1;
        goto out;
    }

    if (cpn_sign_keys_from_config(out, &cfg) < 0) {
        ret = -1;
        goto out;
    }

out:
    cpn_cfg_free(&cfg);

    return ret;
}

int cpn_sign_sig_from_bin(struct cpn_sign_sig *out, const uint8_t *data, size_t datalen)
{
    if (datalen != CPN_CRYPTO_SIGN_SIGBYTES) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid signature length %"PRIuMAX, datalen);
        return -1;
    }

    memcpy(out->data, data, datalen);
    return 0;
}

int cpn_sign_sig_from_proto(struct cpn_sign_sig *out, const SignatureMessage *msg)
{
    if (!msg || msg->data.len != CPN_CRYPTO_SIGN_SIGBYTES)
        return -1;

    memcpy(out->data, msg->data.data, CPN_CRYPTO_SIGN_SIGBYTES);
    return 0;
}

int cpn_sign_sig_to_proto(SignatureMessage **out, const struct cpn_sign_sig *sig)
{
    SignatureMessage *msg = malloc(sizeof(SignatureMessage));
    signature_message__init(msg);

    msg->data.len = CPN_CRYPTO_SIGN_SIGBYTES;
    msg->data.data = malloc(CPN_CRYPTO_SIGN_SIGBYTES);
    memcpy(msg->data.data, sig->data, CPN_CRYPTO_SIGN_SIGBYTES);

    *out = msg;

    return 0;
}

int cpn_sign_sig(struct cpn_sign_sig *out, const struct cpn_sign_sk *key,
        uint8_t *data, size_t datalen)
{
    memset(out, 0, sizeof(*out));

    if (crypto_sign_detached(out->data, NULL, data, datalen, key->data) != 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not sign data");
        return -1;
    }

    return 0;
}

int cpn_sign_sig_verify(const struct cpn_sign_pk *key, const struct cpn_sign_sig *sig,
        uint8_t *data, size_t datalen)
{
    if (crypto_sign_verify_detached(sig->data, data, datalen, key->data) != 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not verify signature");
        return -1;
    }

    return 0;
}
