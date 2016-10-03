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

#include "capone/log.h"

#include "capone/crypto/hash.h"

int cpn_hash_init(struct cpn_hash_state *state, size_t outlen)
{
    if (crypto_generichash_init(&state->state, NULL, 0, outlen) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to initialize hashing state");
        return -1;
    }

    state->outlen = outlen;

    return 0;
}

int cpn_hash_update(struct cpn_hash_state *state, const uint8_t *data, size_t datalen)
{
    if (crypto_generichash_update(&state->state, data, datalen) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to update hash");
        return -1;
    }

    return 0;
}

int cpn_hash_final(uint8_t *out, struct cpn_hash_state *state)
{
    if (crypto_generichash_final(&state->state, out, state->outlen) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to finalize hashing");
        return -1;
    }

    return 0;
}
