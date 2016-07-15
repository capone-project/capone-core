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

#include "lib/common.h"

#include "acl.h"

struct sd_acl_entry {
    struct sd_sign_key_public identity;
    enum sd_acl_right right;

    char wildcard;

    struct sd_acl_entry *next;
};

static bool entry_matches(const struct sd_acl_entry *e,
        const struct sd_sign_key_public *identity, enum sd_acl_right right)
{
    if (memcmp(e->identity.data, identity->data, sizeof(struct sd_sign_key_public)))
        return false;
    if (e->right != right)
        return false;
    return true;
}

static int add_entry(struct sd_acl *acl, struct sd_acl_entry *e)
{
    struct sd_acl_entry *it;

    for (it = acl->entries; it; it = it->next)
        if (e->wildcard && it->wildcard && e->right == it->right)
            break;
        else if (entry_matches(it, &e->identity, e->right))
            break;

    if (it)
        return -1;

    e->next = acl->entries;
    acl->entries = e;

    return 0;
}

void sd_acl_init(struct sd_acl *acl)
{
    acl->entries = NULL;
}

void sd_acl_clear(struct sd_acl *acl)
{
    struct sd_acl_entry *it, *next;

    for (it = acl->entries; it; it = next) {
        next = it->next;

        free(it);
    }

    acl->entries = NULL;
}

int sd_acl_add_right(struct sd_acl *acl,
        const struct sd_sign_key_public *identity,
        enum sd_acl_right right)
{
    struct sd_acl_entry *e;

    e = malloc(sizeof(struct sd_acl_entry));

    memset(e, 0, sizeof(struct sd_acl_entry));
    memcpy(&e->identity, identity, sizeof(struct sd_sign_key_public));
    e->right = right;
    e->wildcard = 0;

    if (add_entry(acl, e) < 0) {
        free(e);
        return -1;
    }

    return 0;
}

int sd_acl_add_wildcard(struct sd_acl *acl,
        enum sd_acl_right right)
{
    struct sd_acl_entry *e;

    e = malloc(sizeof(struct sd_acl_entry));

    memset(e, 0, sizeof(struct sd_acl_entry));
    e->right = right;
    e->wildcard = 1;

    if (add_entry(acl, e) < 0) {
        free(e);
        return -1;
    }

    return 0;
}

int sd_acl_remove_right(struct sd_acl *acl,
        const struct sd_sign_key_public *identity,
        enum sd_acl_right right)
{
    struct sd_acl_entry *it, *prev;

    for (prev = NULL, it = acl->entries; it; prev = it, it = it->next)
        if (entry_matches(it, identity, right))
            break;

    if (!it)
        return -1;

    if (prev)
        prev->next = it->next;
    else
        acl->entries = it->next;

    free(it);

    return 0;
}

bool sd_acl_is_allowed(const struct sd_acl *acl,
        const struct sd_sign_key_public *identity,
        enum sd_acl_right right)
{
    struct sd_acl_entry *it;

    for (it = acl->entries; it; it = it->next)
        if (it->wildcard && it->right == right)
            return true;
        else if (entry_matches(it, identity, right))
            return true;

    return false;
}
