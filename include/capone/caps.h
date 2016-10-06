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
 * \defgroup cpn-caps Capabilities
 * \ingroup cpn-lib
 *
 * @brief Module handling capabilities
 *
 * @{
 */

#ifndef CPN_LIB_CAPS_H
#define CPN_LIB_CAPS_H

#include <stdbool.h>

#include "capone/crypto/sign.h"
#include "capone/proto/core.pb-c.h"

#define CPN_CAP_SECRET_LEN 32

enum cpn_cap_rights {
    CPN_CAP_RIGHT_EXEC = 1 << 0,
    CPN_CAP_RIGHT_TERM = 1 << 1,
    CPN_CAP_RIGHT_DISTRIBUTE = 1 << 2
};

#define CPN_CAP_RIGHTS_ALL ( CPN_CAP_RIGHT_EXEC \
                           | CPN_CAP_RIGHT_TERM \
                           | CPN_CAP_RIGHT_DISTRIBUTE )

struct cpn_cap_secret {
    uint8_t secret[CPN_CAP_SECRET_LEN];
};

struct cpn_cap {
    uint8_t secret[CPN_CAP_SECRET_LEN];

    struct {
        struct cpn_sign_pk identity;
        uint32_t rights;
    } *chain;
    uint8_t chain_depth;
};

/** @brief Parse a capability from strings */
int cpn_cap_from_string(struct cpn_cap **out, const char *string);

/** @brief Parse a capability from strings */
int cpn_cap_to_string(char **out, const struct cpn_cap *cap);

/** @brief Create capability from Protobuf */
int cpn_cap_from_protobuf(struct cpn_cap **out, const CapabilityMessage *msg);

/** @brief Create Protobuf from capability */
int cpn_cap_to_protobuf(CapabilityMessage **out, const struct cpn_cap *cap);

/** @brief Initialize a capability secret
 *
 * This function initializes a new capability secret. The
 * capability secret is used internally only and is used to
 * protect objects. The value shall never be published. To grant
 * access to the guarded object, capabilities can be created
 * referencing the secret.
 *
 * @param[out] cap Initialized capability secret
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_cap_create_secret(struct cpn_cap_secret *out);

/** @brief Create an external reference to an internal capability
 *
 * References to an internal capability can be created, which can
 * subsequently be distributed to a third party, giving this
 * party certain rights on the object referenced by the
 * capability.
 *
 * @param[out] out Newly created capability reference
 * @param[in] root Roto capability to create a reference for
 * @param[in] rights Rights granted with the new capability
 * @param[in] key Public signature key of the entity to whom the
 *            capability shall be granted
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_cap_create_ref(struct cpn_cap **out, const struct cpn_cap *root,
        uint32_t rights, const struct cpn_sign_pk *key);

/** @brief Create an external reference to a capability secret
 *
 * References to a capability secret can be created, which can
 * subsequently be distributed to a third party, giving this
 * party certain rights on the object referenced by the
 * capability.
 *
 * @param[out] out Newly created capability reference
 * @param[in] secret Secret guarding an object
 * @param[in] rights Rights granted with the new capability
 * @param[in] key Public signature key of the entity to whom the
 *            capability shall be granted
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_cap_create_ref_for_secret(struct cpn_cap **out,
        const struct cpn_cap_secret *secret,
        uint32_t rights, const struct cpn_sign_pk *key);

/** @brief Free an allocated capability */
void cpn_cap_free(struct cpn_cap *cap);

/** @brief Verify that the given capability is valid
 *
 * Verify that the capability is in fact valid for the given
 * identity's key and its access rights.
 *
 * @param[in] ref Capability to verify
 * @param[in] key Key of the party that wants to use the
 *            capability
 * @param[in] rights Rights requested for the capability
 * @return <code>0</code> if the capability is valid for the
 *         given key and rights, <code>-1</code> otherwise
 */
int cpn_caps_verify(const struct cpn_cap *ref,
        const struct cpn_cap_secret *secret,
        const struct cpn_sign_pk *key, uint32_t rights);

#endif

/** @} */
