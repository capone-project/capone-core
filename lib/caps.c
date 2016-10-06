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
#include <pthread.h>

#include <arpa/inet.h>

#include "capone/buf.h"
#include "capone/caps.h"
#include "capone/common.h"
#include "capone/list.h"
#include "capone/log.h"

#include "capone/crypto/hash.h"

static int hash_secret(uint8_t *out,
        uint32_t rights,
        const uint8_t *secret,
        const struct cpn_sign_pk *key)
{
    struct cpn_hash_state state;
    uint32_t nlrights = htonl(rights);
    int err = 0;

    err |= cpn_hash_init(&state, CPN_CAP_SECRET_LEN);
    err |= cpn_hash_update(&state, key->data, sizeof(key->data));
    err |= cpn_hash_update(&state, (unsigned char *) &nlrights, sizeof(nlrights));
    err |= cpn_hash_update(&state, (unsigned char *) secret, CPN_CAP_SECRET_LEN);
    err |= cpn_hash_final(out, &state);

    return err;
}

int cpn_cap_from_string(struct cpn_cap **out, const char *string)
{
    struct cpn_cap *cap;
    uint32_t i, rights, chain_depth = 0;
    int err = -1;
    const char *ptr;

    cap = malloc(sizeof(struct cpn_cap));
    cap->chain = NULL;

    for (ptr = string; *ptr != '\0'; ptr++) {
        if (*ptr == '|')
            chain_depth++;
    }

    ptr = strchr(string, chain_depth ? '|' : '\0');

    if ((ptr - string) != CPN_CAP_SECRET_LEN * 2) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid secret");
        goto out;
    }

    if (parse_hex(cap->secret, sizeof(cap->secret), string, ptr - string) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid hex secret");
        goto out;
    }

    if (*ptr == '\0') {
        cpn_log(LOG_LEVEL_ERROR, "Capability has no chain");
        goto out;
    }

    cap->chain = malloc(sizeof(*cap->chain) * chain_depth);
    cap->chain_depth = chain_depth;
    rights = CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM | CPN_CAP_RIGHT_DISTRIBUTE;

    for (i = 0; i < chain_depth; i++) {
        string = ++ptr;
        ptr = strchr(string, ':');

        if (ptr == NULL) {
            cpn_log(LOG_LEVEL_ERROR, "Capability chain entry without rights");
            goto out;
        }

        if (parse_hex(cap->chain[i].identity.data, sizeof(struct cpn_sign_pk),
                    string, ptr - string) < 0)
        {
            cpn_log(LOG_LEVEL_ERROR, "Capability chain entry invalid identity");
            goto out;
        }

        cap->chain[i].rights = 0;
        while (*++ptr != '\0' && *ptr != '|') {
            switch (*ptr) {
                case 'x':
                    cap->chain[i].rights |= CPN_CAP_RIGHT_EXEC;
                    break;
                case 't':
                    cap->chain[i].rights |= CPN_CAP_RIGHT_TERM;
                    break;
                case 'd':
                    cap->chain[i].rights |= CPN_CAP_RIGHT_DISTRIBUTE;
                    break;
                case '|':
                    continue;
                default:
                    goto out;
            }
        }

        if (cap->chain[i].rights == 0 || (cap->chain[i].rights & ~rights))
            goto out;
        rights = cap->chain[i].rights;
    }

    err = 0;
    *out = cap;

out:
    if (err) {
        free(cap->chain);
        free(cap);
    }
    return err;
}

int cpn_cap_to_string(char **out, const struct cpn_cap *cap)
{
    struct cpn_buf buf = CPN_BUF_INIT;
    struct cpn_sign_pk_hex hex;
    uint32_t i;

    if (cpn_buf_append_hex(&buf, cap->secret, sizeof(cap->secret)) < 0)
        goto out_err;

    for (i = 0; i < cap->chain_depth; i++) {
        if (!cap->chain[i].rights)
            goto out_err;

        cpn_sign_pk_hex_from_key(&hex, &cap->chain[i].identity);
        cpn_buf_printf(&buf, "|%s:", hex.data);

        if (cap->chain[i].rights & CPN_CAP_RIGHT_EXEC)
            cpn_buf_append(&buf, "x");
        if (cap->chain[i].rights & CPN_CAP_RIGHT_TERM)
            cpn_buf_append(&buf, "t");
        if (cap->chain[i].rights & CPN_CAP_RIGHT_DISTRIBUTE)
            cpn_buf_append(&buf, "d");
    }

    *out = buf.data;

    return 0;

out_err:
    cpn_buf_clear(&buf);
    return -1;
}

int cpn_cap_from_protobuf(struct cpn_cap **out, const CapabilityMessage *msg)
{
    struct cpn_cap *cap = NULL;
    uint32_t i;

    if (!msg)
        goto out_err;
    if (msg->secret.len != CPN_CAP_SECRET_LEN)
        goto out_err;
    if (msg->n_chain == 0 || msg->n_chain > UINT8_MAX)
        goto out_err;

    cap = malloc(sizeof(struct cpn_cap));
    memcpy(cap->secret, msg->secret.data, CPN_CAP_SECRET_LEN);
    cap->chain_depth = msg->n_chain;
    cap->chain = malloc(sizeof(*cap->chain) * cap->chain_depth);

    for (i = 0; i < msg->n_chain; i++) {
        cap->chain[i].rights = msg->chain[i]->rights;
        if (cpn_sign_pk_from_proto(&cap->chain[i].identity, msg->chain[i]->identity) < 0)
            goto out_err;
    }

    *out = cap;

    return 0;

out_err:
    cpn_cap_free(cap);

    return -1;
}

int cpn_cap_to_protobuf(CapabilityMessage **out, const struct cpn_cap *cap)
{
    CapabilityMessage *msg;
    uint32_t i;

    msg = malloc(sizeof(CapabilityMessage));
    capability_message__init(msg);

    msg->secret.data = malloc(CPN_CAP_SECRET_LEN);
    msg->secret.len = CPN_CAP_SECRET_LEN;
    msg->n_chain = cap->chain_depth;
    msg->chain = malloc(sizeof(*msg->chain) * cap->chain_depth);

    for (i = 0;  i < cap->chain_depth; i++) {
        CapabilityMessage__Chain *chain = malloc(sizeof(*chain));
        capability_message__chain__init(chain);
        chain->rights = cap->chain[i].rights;
        cpn_sign_pk_to_proto(&chain->identity, &cap->chain[i].identity);
        msg->chain[i] = chain;
    }

    memcpy(msg->secret.data, cap->secret, CPN_CAP_SECRET_LEN);

    *out = msg;

    return 0;
}

int cpn_cap_create_secret(struct cpn_cap_secret *out)
{
    cpn_randombytes(out->secret, CPN_CAP_SECRET_LEN);

    return 0;
}

int cpn_cap_create_ref(struct cpn_cap **out, const struct cpn_cap *root,
        uint32_t rights, const struct cpn_sign_pk *key)
{
    struct cpn_cap *cap;

    *out = NULL;

    if (!root->chain_depth || !root->chain) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid capability chain");
        return -1;
    }

    if (rights & ~root->chain[root->chain_depth - 1].rights) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid right expansion for new capability");
        return -1;
    }

    if (!(CPN_CAP_RIGHT_DISTRIBUTE & root->chain[root->chain_depth - 1].rights)) {
        cpn_log(LOG_LEVEL_ERROR, "Trying to derive from non-distributable capability");
        return -1;
    }

    cap = malloc(sizeof(struct cpn_cap));

    if (hash_secret(cap->secret, rights, root->secret, key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not compute capability secret");
        free(cap);
        return -1;
    }

    cap->chain_depth = root->chain_depth + 1;
    cap->chain = malloc(sizeof(*cap->chain) * cap->chain_depth);
    memcpy(cap->chain, root->chain, sizeof(*root->chain) * root->chain_depth);
    memcpy(&cap->chain[root->chain_depth].identity, key, sizeof(struct cpn_sign_pk));
    cap->chain[root->chain_depth].rights = rights;

    *out = cap;

    return 0;
}

int cpn_cap_create_ref_for_secret(struct cpn_cap **out,
        const struct cpn_cap_secret *secret,
        uint32_t rights, const struct cpn_sign_pk *key)
{
    struct cpn_cap *cap;

    *out = NULL;

    cap = malloc(sizeof(struct cpn_cap));

    if (hash_secret(cap->secret, rights, secret->secret, key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not compute capability secret");
        free(cap);
        return -1;
    }

    cap->chain_depth = 1;
    cap->chain = malloc(sizeof(*cap->chain));
    memcpy(&cap->chain[0].identity, key, sizeof(struct cpn_sign_pk));
    cap->chain[0].rights = rights;

    *out = cap;

    return 0;
}

void cpn_cap_free(struct cpn_cap *cap)
{
    if (!cap)
        return;

    free(cap->chain);
    free(cap);
}

int cpn_caps_verify(const struct cpn_cap *ref,
        const struct cpn_cap_secret *secret,
        const struct cpn_sign_pk *key, uint32_t right)
{
    uint8_t hash[CPN_CAP_SECRET_LEN];
    uint32_t i, rights;

    if (ref->chain_depth == 0)
        return -1;
    if (memcmp(key, &ref->chain[ref->chain_depth - 1].identity, sizeof(struct cpn_sign_pk)))
        return -1;
    if (!(ref->chain[ref->chain_depth - 1].rights & right))
        return -1;

    rights = CPN_CAP_RIGHTS_ALL;
    memcpy(hash, secret->secret, sizeof(hash));

    for (i = 0; i < ref->chain_depth; i++) {
        /* Check whether the previous set of rights allows for distribution */
        if (!(rights & CPN_CAP_RIGHT_DISTRIBUTE)) {
            cpn_log(LOG_LEVEL_ERROR, "Capability derived from non-distributable capability");
            return -1;
        }

        /* Check whether we extend previous rights */
        if (ref->chain[i].rights & ~rights) {
            cpn_log(LOG_LEVEL_ERROR, "Derived capability extends previous rights");
            return -1;
        }

        if (hash_secret(hash, ref->chain[i].rights, hash, &ref->chain[i].identity) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to compute capability secret");
            return -1;
        }

        rights = ref->chain[i].rights;
    }

    if (right & ~rights)
        return -1;
    if (memcmp(hash, ref->secret, CPN_CAP_SECRET_LEN))
        return -1;

    return 0;
}
