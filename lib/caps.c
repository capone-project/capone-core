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

#include "caps.h"

#include "lib/common.h"
#include "lib/log.h"

struct caps {
    uint32_t objectid;
    uint8_t secret[SD_CAP_SECRET_LEN];
    struct caps *next;
};

static struct caps *clist;

static int hash(uint8_t *out,
        uint32_t objectid,
        uint32_t rights,
        uint8_t *secret,
        const struct cpn_sign_key_public *key)
{
    crypto_generichash_state state;
    uint8_t hash[SD_CAP_SECRET_LEN];

    crypto_generichash_init(&state, NULL, 0, sizeof(secret));

    crypto_generichash_update(&state, key->data, sizeof(key->data));
    crypto_generichash_update(&state, (unsigned char *) &objectid, sizeof(objectid));
    crypto_generichash_update(&state, (unsigned char *) &rights, sizeof(rights));
    crypto_generichash_update(&state, (unsigned char *) secret, SD_CAP_SECRET_LEN);

    crypto_generichash_final(&state, hash, sizeof(hash));

    memcpy(out, hash, SD_CAP_SECRET_LEN);

    return 0;
}

int cpn_cap_parse(struct cpn_cap *out, const char *id, const char *secret, enum cpn_cap_rights rights)
{
    uint32_t objectid;
    uint8_t hash[SD_CAP_SECRET_LEN];
    int err = -1;

    if (parse_uint32t(&objectid, id) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid session ID");
        goto out;
    }

    if (strlen(secret) != SD_CAP_SECRET_LEN * 2) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid secret length");
        goto out;
    }

    if (sodium_hex2bin(hash, sizeof(hash), secret, strlen(secret),
                NULL, NULL, NULL) != 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Invalid secret");
        goto out;
    }

    out->objectid = objectid;
    out->rights = rights;
    memcpy(out->secret, hash, SD_CAP_SECRET_LEN);

    err = 0;

out:
    return err;
}

int cpn_cap_from_protobuf(struct cpn_cap *out, const CapabilityMessage *msg)
{
    if (msg->secret.len != SD_CAP_SECRET_LEN)
        return -1;

    out->objectid = msg->objectid;
    out->rights = msg->rights;
    memcpy(out->secret, msg->secret.data, SD_CAP_SECRET_LEN);

    return 0;
}

int cpn_cap_to_protobuf(CapabilityMessage *out, const struct cpn_cap *cap)
{
    capability_message__init(out);
    out->objectid = cap->objectid;
    out->rights = cap->rights;
    out->secret.data = malloc(SD_CAP_SECRET_LEN);
    out->secret.len = SD_CAP_SECRET_LEN;
    memcpy(out->secret.data, cap->secret, SD_CAP_SECRET_LEN);

    return 0;
}

int cpn_caps_add(uint32_t objectid)
{
    struct caps *e, *cap;

    for (e = clist; e; e = e->next) {
        if (e->objectid == objectid)
            return -1;
    }

    cap = malloc(sizeof(struct caps));
    cap->objectid = objectid;
    randombytes_buf(cap->secret, SD_CAP_SECRET_LEN);
    cap->next = clist;

    clist = cap;

    return 0;
}

void cpn_caps_clear(void)
{
    struct caps *e, *next;

    for (e = clist; e; e = next) {
        next = e->next;
        free(e);
    }

    clist = NULL;
}

int cpn_caps_delete(uint32_t objectid)
{
    struct caps *it, *prev, *next;
    int ret = -1;

    for (prev = NULL, it = clist; it; prev = it, it = next) {
        next = it->next;

        if (it->objectid != objectid)
            continue;

        if (prev)
            prev->next = it->next;
        else
            clist = it->next;

        free(it);

        ret = 0;
    }

    return ret;
}

int cpn_caps_create_reference(struct cpn_cap *out, uint32_t objectid, uint32_t rights, const struct cpn_sign_key_public *key)
{
    struct caps *e;

    for (e = clist; e; e = e->next) {
        if (e->objectid == objectid)
            break;
    }

    if (!e)
        return -1;

    out->objectid = objectid;
    out->rights = rights;
    hash(out->secret, objectid, rights, e->secret, key);

    return 0;
}

int cpn_caps_verify(const struct cpn_cap *ref, const struct cpn_sign_key_public *key, uint32_t rights)
{
    struct caps *e;
    uint8_t secret[SD_CAP_SECRET_LEN];

    if (rights & ~ref->rights)
        return -1;

    for (e = clist; e; e = e->next) {
        /* Object ID must match */
        if (ref->objectid != e->objectid)
            continue;
        /* Secret must the root secret */
        if (hash(secret, ref->objectid, ref->rights, e->secret, key) < 0)
            continue;
        if (memcmp(secret, ref->secret, SD_CAP_SECRET_LEN))
            continue;

        return 0;
    }

    return -1;
}
