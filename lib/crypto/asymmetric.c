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
#include <sodium.h>

#include "capone/log.h"

#include "capone/crypto/asymmetric.h"

int cpn_asymmetric_keys_generate(struct cpn_asymmetric_keys *out)
{
    return crypto_box_keypair(out->pk.data, out->sk.data);
}

int cpn_asymmetric_pk_from_bin(struct cpn_asymmetric_pk *out, uint8_t *pk, size_t pklen)
{
    if (pklen != crypto_box_PUBLICKEYBYTES) {
        cpn_log(LOG_LEVEL_ERROR, "Passed in buffer does not match required public encrypt key length");
        return -1;
    }

    memcpy(out->data, pk, sizeof(out->data));

    return 0;
}
