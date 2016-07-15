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
 * \defgroup sd-caps Capabilities
 * \ingroup sd-lib
 *
 * @brief Module handling capabilities
 *
 * @{
 */

#ifndef SD_LIB_CAPS_H
#define SD_LIB_CAPS_H

#include <stdbool.h>
#include "lib/keys.h"

enum sd_cap_rights {
    SD_CAP_RIGHT_EXEC = 1 << 0,
    SD_CAP_RIGHT_TERM = 1 << 1
};

struct sd_cap {
    uint32_t objectid;
    uint32_t rights;
    uint32_t secret;
};

/** @brief Add a new internal capability
 *
 * This function adds a new global internal capabilty which
 * has as object identifier the given objectid. The internal
 * capability can later on be used to get external references,
 * which may be distributed to third parties.
 *
 * @param[in] objectid Object ID that should be saved inside t he
 *            internal capability
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int sd_caps_add(uint32_t objectid);

/** @brief Delete internal capability
 *
 * Delete an existing internal capability with the given object
 * identifier.
 *
 * @param[in] objectid Object ID by which the capability shall
 *            be deleted.
 * @return <code>0</code> on success, <code>-1</code> if no
 *         capability was deleted
 */
int sd_caps_delete(uint32_t objectid);

/** @brief Delete all internal capabilities */
void sd_caps_clear(void);

/** @brief Create an external reference to an internal capability
 *
 * References to an internal capability can be created, which can
 * subsequently be distributed to a third party, giving this
 * party certain rights on the object referenced by the
 * capability.
 *
 * @param[out] out Newly created capability reference
 * @param[in] objectid Object ID for which the reference shall be
 *            created
 * @param[in] rights Rights granted with the new capability
 * @param[in] key Public signature key of the entity to whom the
 *            capability shall be granted
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int sd_caps_create_reference(struct sd_cap *out, uint32_t objectid, uint32_t rights, const struct sd_sign_key_public *key);

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
int sd_caps_verify(const struct sd_cap *ref, const struct sd_sign_key_public *key, uint32_t rights);

#endif

/** @} */
