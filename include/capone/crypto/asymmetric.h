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

#ifndef CPN_LIB_CRYPTO_ASYMMETRIC_H
#define CPN_LIB_CRYPTO_ASYMMETRIC_H

#include <stddef.h>
#include <stdint.h>

#define CPN_CRYPTO_ASYMMETRIC_SKBYTES 32
#define CPN_CRYPTO_ASYMMETRIC_PKBYTES 32

/** @brief Secret encryption key used to decrypt data */
struct cpn_asymmetric_sk {
    uint8_t data[CPN_CRYPTO_ASYMMETRIC_SKBYTES];
};

/** @brief Public encryption key used to encrypt data */
struct cpn_asymmetric_pk {
    uint8_t data[CPN_CRYPTO_ASYMMETRIC_PKBYTES];
};

/** @brief Encryption key pair */
struct cpn_asymmetric_keys {
    struct cpn_asymmetric_sk sk;
    struct cpn_asymmetric_pk pk;
};

/** @brief Generate a new encryption key pair
 *
 * @param[out] out Pointer to store public encryption key pair at.
 * @return <code>0</code>
 */
int cpn_asymmetric_keys_generate(struct cpn_asymmetric_keys *out);

/** @brief Read a public encryption key from binary data
 *
 * @param[out] out Pointer to store public encryption key at.
 * @param[in] pk Binary representation of the key.
 * @param[in] pklen Length of the binary data.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_asymmetric_pk_from_bin(struct cpn_asymmetric_pk *out,
        uint8_t *pk, size_t pklen);

#endif
