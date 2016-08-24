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
#include <string.h>
#include <pthread.h>

#include "capone/caps.h"
#include "capone/common.h"
#include "capone/list.h"
#include "capone/log.h"

static int hash(uint8_t *out,
        uint32_t rights,
        const uint8_t *secret,
        const struct cpn_sign_key_public *key)
{
    crypto_generichash_state state;
    uint8_t hash[CPN_CAP_SECRET_LEN];

    crypto_generichash_init(&state, NULL, 0, sizeof(secret));

    crypto_generichash_update(&state, key->data, sizeof(key->data));
    crypto_generichash_update(&state, (unsigned char *) &rights, sizeof(rights));
    crypto_generichash_update(&state, (unsigned char *) secret, CPN_CAP_SECRET_LEN);

    crypto_generichash_final(&state, hash, sizeof(hash));

    memcpy(out, hash, CPN_CAP_SECRET_LEN);

    return 0;
}

int cpn_cap_from_string(struct cpn_cap **out, const char *string)
{
    struct cpn_cap *cap;
    uint8_t secret[CPN_CAP_SECRET_LEN];
    uint32_t rights = 0;
    char *ptr;
    int err = -1;

    ptr = strchr(string, ':');
    if (ptr == NULL || (ptr - string) != CPN_CAP_SECRET_LEN * 2) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid secret");
        goto out;
    }

    if (parse_hex(secret, sizeof(secret), string, ptr - string) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid hex secret");
        goto out;
    }

    if (*(ptr + 1) == '\0') {
        cpn_log(LOG_LEVEL_ERROR, "Capabilities has no rights");
        goto out;
    }

    while (*++ptr != '\0') {
        switch (*ptr) {
            case 'x':
                rights |= CPN_CAP_RIGHT_EXEC;
                break;
            case 't':
                rights |= CPN_CAP_RIGHT_TERM;
                break;
            default:
                return -1;
        }
    }

    cap = malloc(sizeof(struct cpn_cap));
    cap->rights = rights;
    memcpy(cap->secret, secret, CPN_CAP_SECRET_LEN);
    *out = cap;

    err = 0;

out:
    return err;
}

int rights_to_string(char **ptr, uint32_t rights)
{
    if (!rights)
        return -1;
    if (rights & CPN_CAP_RIGHT_EXEC)
        *(*ptr)++ = 'x';
    if (rights & CPN_CAP_RIGHT_TERM)
        *(*ptr)++ = 't';
    return 0;
}

int cpn_cap_to_string(char **out, const struct cpn_cap *cap)
{
    char *string, *ptr;
    uint32_t len = 0;

    if (!cap->rights)
        return -1;

    len += sizeof(cap->secret) * 2;
    len += 1; /* separator */
    len += (cap->rights & CPN_CAP_RIGHT_EXEC);
    len += (cap->rights & CPN_CAP_RIGHT_TERM);

    ptr = string = malloc(len + 1);

    if (sodium_bin2hex(ptr, len, cap->secret, sizeof(cap->secret)) == NULL)
        goto out_err;
    ptr += sizeof(cap->secret) * 2;

    *ptr++ = ':';
    if (rights_to_string(&ptr, cap->rights) < 0)
        goto out_err;
    *ptr++ = '\0';

    *out = string;

    return 0;

out_err:
    free(string);
    return -1;
}

int cpn_cap_from_protobuf(struct cpn_cap **out, const CapabilityMessage *msg)
{
    struct cpn_cap *cap;

    if (msg->secret.len != CPN_CAP_SECRET_LEN)
        return -1;

    cap = malloc(sizeof(struct cpn_cap));
    cap->rights = msg->rights;
    memcpy(cap->secret, msg->secret.data, CPN_CAP_SECRET_LEN);

    *out = cap;

    return 0;
}

int cpn_cap_to_protobuf(CapabilityMessage *out, const struct cpn_cap *cap)
{
    capability_message__init(out);
    out->rights = cap->rights;
    out->secret.data = malloc(CPN_CAP_SECRET_LEN);
    out->secret.len = CPN_CAP_SECRET_LEN;
    memcpy(out->secret.data, cap->secret, CPN_CAP_SECRET_LEN);

    return 0;
}

int cpn_cap_create_root(struct cpn_cap **out)
{
    struct cpn_cap *cap;

    cap = malloc(sizeof(struct cpn_cap));
    cap->rights = CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM;
    randombytes_buf(cap->secret, CPN_CAP_SECRET_LEN);

    *out = cap;

    return 0;
}

int cpn_cap_create_ref(struct cpn_cap **out, const struct cpn_cap *root,
        uint32_t rights, const struct cpn_sign_key_public *key)
{
    struct cpn_cap *cap;

    cap = malloc(sizeof(struct cpn_cap));
    cap->rights = rights;
    hash(cap->secret, rights, root->secret, key);

    *out = cap;

    return 0;
}

void cpn_cap_free(struct cpn_cap *cap)
{
    if (!cap)
        return;

    free(cap);
}

int cpn_caps_verify(const struct cpn_cap *ref, const struct cpn_cap *root,
        const struct cpn_sign_key_public *key, uint32_t rights)
{
    uint8_t secret[CPN_CAP_SECRET_LEN];

    if (rights & ~ref->rights)
        return -1;

    /* Secret must match the root secret */
    if (hash(secret, ref->rights, root->secret, key) < 0)
        return -1;
    if (memcmp(secret, ref->secret, CPN_CAP_SECRET_LEN))
        return -1;

    return 0;
}
