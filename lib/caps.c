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

struct caps {
    struct entry {
        uint32_t objectid;
        uint32_t secret;
        struct entry *next;
    } *l;
};

static struct caps clist;

static uint32_t hash(uint32_t objectid,
        uint32_t rights,
        uint32_t secret,
        const struct sd_sign_key_public *key)
{
    crypto_generichash_state state;
    uint32_t hash;

    crypto_generichash_init(&state, NULL, 0, sizeof(secret));

    crypto_generichash_update(&state, key->data, sizeof(key->data));
    crypto_generichash_update(&state, (unsigned char *) &objectid, sizeof(objectid));
    crypto_generichash_update(&state, (unsigned char *) &rights, sizeof(rights));
    crypto_generichash_update(&state, (unsigned char *) &secret, sizeof(secret));

    crypto_generichash_final(&state, (unsigned char *) &hash, sizeof(hash));

    return hash;
}

int sd_cap_from_protobuf(struct sd_cap *out, const CapabilityMessage *msg)
{
    out->objectid = msg->objectid;
    out->rights = msg->rights;
    out->secret = msg->secret;

    return 0;
}

int sd_cap_to_protobuf(CapabilityMessage *out, const struct sd_cap *cap)
{
    capability_message__init(out);
    out->objectid = cap->objectid;
    out->rights = cap->rights;
    out->secret = cap->secret;

    return 0;
}

int sd_caps_add(uint32_t objectid)
{
    struct entry *e, *cap;

    cap = malloc(sizeof(struct entry));
    cap->objectid = objectid;
    cap->secret = randombytes_random();
    cap->next = NULL;

    for (e = clist.l; e; e = e->next) {
        if (e->objectid == objectid)
            return -1;
    }

    if (e)
        e->next = cap;
    else
        clist.l = cap;

    return 0;
}

void sd_caps_clear(void)
{
    struct entry *e, *next;

    for (e = clist.l; e; e = next) {
        next = e->next;
        free(e);
    }

    clist.l = NULL;
}

int sd_caps_delete(uint32_t objectid)
{
    struct entry *e, *prev;
    int ret = 0;

    for (prev = NULL, e = clist.l; e; prev = e, e = e->next) {
        if (e->objectid != objectid)
            continue;

        if (prev)
            prev->next = e->next;
        else
            clist.l->next = e->next;

        free(e);

        ret = 1;
    }

    return ret;
}

int sd_caps_create_reference(struct sd_cap *out, uint32_t objectid, uint32_t rights, const struct sd_sign_key_public *key)
{
    struct sd_cap *cap;
    struct entry *e;

    for (e = clist.l; e; e = e->next) {
        if (e->objectid == objectid)
            break;
    }

    if (!e)
        return -1;

    cap = malloc(sizeof(struct sd_cap));
    cap->objectid = objectid;
    cap->rights = rights;
    cap->secret = hash(objectid, rights, e->secret, key);

    memcpy(out, cap, sizeof(struct sd_cap));

    return 0;
}

int sd_caps_verify(const struct sd_cap *ref, const struct sd_sign_key_public *key, uint32_t rights)
{
    struct entry *e;

    if (rights & ~ref->rights)
        return -1;

    for (e = clist.l; e; e = e->next) {
        /* Object ID must match */
        if (ref->objectid != e->objectid)
            continue;
        /* Secret must the root secret */
        if (ref->secret != hash(ref->objectid, ref->rights, e->secret, key))
            continue;

        return 0;
    }

    return -1;
}
