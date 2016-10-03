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

/**
 * \defgroup cpn-acl Access control list management
 * \ingroup cpn-lib
 *
 * @brief Module for handling access control lists
 *
 * This module provides a struct and functions to manage access
 * control lists (ACL). ACLs can be attached to other objects and
 * will then handle who is allowed to perform actions on
 * this list.
 *
 * @{
 */

#ifndef CPN_LIB_ACL_H
#define CPN_LIB_ACL_H

#include <stdbool.h>

#include "capone/crypto/sign.h"

/**
 * The rights that can be given for an identity.
 */
enum cpn_acl_right {
    /** Allow the identity to execute the action the ACL is
     * associated with */
    CPN_ACL_RIGHT_EXEC,
    /** Allow the identity to revoke access to the object */
    CPN_ACL_RIGHT_TERMINATE
};

/** An entry in the access control list */
struct cpn_acl_entry;

/** The access control list.
 *
 * The access control list manages all entities allowed to
 * perform actions allowed for the object the ACL is related to.
 * Each entry gives a single right to a single identity. When no
 * entry for an identity exists, this identity is not allowed to
 * execute any actions on this object.
 */
struct cpn_acl {
    struct cpn_acl_entry *entries;
};

/** Initialize an access control list */
#define CPN_ACL_INIT { NULL }

/** @brief Initialize an ACL
 *
 * Initialize the given ACL so that no identity is granted any
 * rights.
 *
 * @param[in] acl The ACL to initialize
 */
void cpn_acl_init(struct cpn_acl *acl);

/** @brief Remove all entries from the ACL
 *
 * Remove all entries from the ACL so that no entity is allowed
 * to perform any actions.
 *
 * @param[in] acl The ACL to clear
 */
void cpn_acl_clear(struct cpn_acl *acl);

/** @brief Add rights to the access control list
 *
 * This function adds a specific right for an identity to the
 * given access control list. Adding the right will only succeed
 * if it has not previously been added to the ACL.
 *
 * @param[in] acl The access control list to add a right to
 * @param[in] identity The identity for which to add the right
 * @param[in] right The right to add for the entity
 * @return <code>0</code> on success, <code>-1</code> if the
 *         right has already been added before
 */
int cpn_acl_add_right(struct cpn_acl *acl,
        const struct cpn_sign_pk *identity,
        enum cpn_acl_right right);

/** @brief Add permission to execute right for all identities
 *
 * A wildcard grants permission for the right to every identity
 * connecting to a service.
 */
int cpn_acl_add_wildcard(struct cpn_acl *acl,
        enum cpn_acl_right right);

/** @brief Remove rights from the access control list
 *
 * This function removes the right to perform a single action for
 * an identity. After executing this function, the identity will
 * not be allowed to perform the action associated to the right
 * on the object the ACL is related to.
 *
 * The function will fail if the right has not been attached to
 * the ACL.
 *
 * @param[in] acl The ACL to remove the right for
 * @param[in] identity The identity to remove the right for
 * @param[in] right The right to remove
 * @return <code>0</code> if the right was removed,
 *         <code>-1</code> if the right was not present in the ACL
 */
int cpn_acl_remove_right(struct cpn_acl *acl,
        const struct cpn_sign_pk *identity,
        enum cpn_acl_right right);

/** @brief Check if the identity has a right
 *
 * Check if an entry is present in the ACL that grants an
 * identity a certain right. When no rights have been granted to
 * the identity or the right that is searched for has not been
 * granted, the identity is deemed to have no access.
 *
 * @param[in] acl The ACL to search in
 * @param[in] identity The identity which is checked to have been
 *            granted a right
 * @param[in] right The right to check for
 * @return <code>true</code> if the right has been granted,
 *         <code>false</code> otherwise
 */
bool cpn_acl_is_allowed(const struct cpn_acl *acl,
        const struct cpn_sign_pk *identity,
        enum cpn_acl_right right);

#endif

/** @} */
