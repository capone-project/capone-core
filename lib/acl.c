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

struct cpn_acl_entry {
    struct cpn_sign_key_public identity;
    enum cpn_acl_right right;

    char wildcard;

    struct cpn_acl_entry *next;
};

static bool entry_matches(const struct cpn_acl_entry *e,
        const struct cpn_sign_key_public *identity, enum cpn_acl_right right)
{
    if (memcmp(e->identity.data, identity->data, sizeof(struct cpn_sign_key_public)))
        return false;
    if (e->right != right)
        return false;
    return true;
}

static int add_entry(struct cpn_acl *acl, struct cpn_acl_entry *e)
{
    struct cpn_acl_entry *it;

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

void cpn_acl_init(struct cpn_acl *acl)
{
    acl->entries = NULL;
}

void cpn_acl_clear(struct cpn_acl *acl)
{
    struct cpn_acl_entry *it, *next;

    for (it = acl->entries; it; it = next) {
        next = it->next;

        free(it);
    }

    acl->entries = NULL;
}

int cpn_acl_add_right(struct cpn_acl *acl,
        const struct cpn_sign_key_public *identity,
        enum cpn_acl_right right)
{
    struct cpn_acl_entry *e;

    e = malloc(sizeof(struct cpn_acl_entry));

    memset(e, 0, sizeof(struct cpn_acl_entry));
    memcpy(&e->identity, identity, sizeof(struct cpn_sign_key_public));
    e->right = right;
    e->wildcard = 0;

    if (add_entry(acl, e) < 0) {
        free(e);
        return -1;
    }

    return 0;
}

int cpn_acl_add_wildcard(struct cpn_acl *acl,
        enum cpn_acl_right right)
{
    struct cpn_acl_entry *e;

    e = malloc(sizeof(struct cpn_acl_entry));

    memset(e, 0, sizeof(struct cpn_acl_entry));
    e->right = right;
    e->wildcard = 1;

    if (add_entry(acl, e) < 0) {
        free(e);
        return -1;
    }

    return 0;
}

int cpn_acl_remove_right(struct cpn_acl *acl,
        const struct cpn_sign_key_public *identity,
        enum cpn_acl_right right)
{
    struct cpn_acl_entry *it, *prev;

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

bool cpn_acl_is_allowed(const struct cpn_acl *acl,
        const struct cpn_sign_key_public *identity,
        enum cpn_acl_right right)
{
    struct cpn_acl_entry *it;

    for (it = acl->entries; it; it = it->next)
        if (it->wildcard && it->right == right)
            return true;
        else if (entry_matches(it, identity, right))
            return true;

    return false;
}
