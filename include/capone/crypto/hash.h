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

#ifndef CPN_LIB_CRYPTO_HASH_H
#define CPN_LIB_CRYPTO_HASH_H

#include <sodium/crypto_generichash.h>

#define CPN_HASH_BYTES 64

struct cpn_hash_state {
    crypto_generichash_state state;
    size_t outlen;
};

/** @brief Initialize the hash state */
int cpn_hash_init(struct cpn_hash_state *state, size_t outlen);

/** @brief Update the hash with new data */
int cpn_hash_update(struct cpn_hash_state *state, const uint8_t *data, size_t datalen);

/** @brief Compute the hash */
int cpn_hash_final(uint8_t *out, struct cpn_hash_state *state);

#endif
