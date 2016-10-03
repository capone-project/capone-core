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
 * \defgroup cpn-keys Key Management
 * \ingroup cpn-lib
 *
 * @brief Module for key handling
 *
 * This module provides several structs for keys and functions
 * used to read data into these structs. Like this, we can
 * provide opaque handling of the different structures required
 * for different kind of keys.
 *
 * The module provides three kind of keys:
 *  - Signing key pairs provide keys used for signing and
 *    verifying data. They are usually used to represent an
 *    entity and are thus long-term keys.
 *  - Encrypt keys pairs are used for encrypting and decrypting
 *    data with an asymmetric key pair. Signature keys cannot be
 *    used for this use case.
 *  - Symmetric keys are used for encrypting data with a single
 *    key shared between participating parties.
 *
 * @{
 */

#ifndef CPN_LIB_CRYPTO_SYMMETRIC_H
#define CPN_LIB_CRYPTO_SYMMETRIC_H

#define CPN_CRYPTO_SYMMETRIC_KEYBYTES 32
#define CPN_CRYPTO_SYMMETRIC_NONCEBYTES 24
#define CPN_CRYPTO_SYMMETRIC_MACBYTES 16

#include "capone/cfg.h"

/** @brief Symmetric key used to encrypt/decrypt data */
struct cpn_symmetric_key {
    uint8_t data[CPN_CRYPTO_SYMMETRIC_KEYBYTES];
};

/** @brief Hex representation of a symmetric key */
struct cpn_symmetric_key_hex {
    char data[CPN_CRYPTO_SYMMETRIC_KEYBYTES * 2 + 1];
};

struct cpn_symmetric_key_nonce {
    uint8_t data[CPN_CRYPTO_SYMMETRIC_NONCEBYTES];
};

/** @brief Generate a new symmetric key
 *
 * @param[out] out Pointer to store symmetric key at.
 * @return <code>0</code>
 */
int cpn_symmetric_key_generate(struct cpn_symmetric_key *out);

/** @brief Read a symmetric key from hex
 *
 * @param[out] out Pointer to store symmetric key at.
 * @param[in] hex Hex representation of the key.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_symmetric_key_from_hex(struct cpn_symmetric_key *out, const char *hex);

/** @brief Read a symmetric key from binary data
 *
 * @param[out] out Pointer to store symmetric key at.
 * @param[in] pk Binary representation of the key.
 * @param[in] pklen Length of the binary data.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_symmetric_key_from_bin(struct cpn_symmetric_key *out, const uint8_t *key, size_t keylen);

/** @brief Read a symmetric key from binary data
 *
 * @param[out] out Pointer to store symmetric key at.
 * @param[in] pk Binary representation of the key.
 * @param[in] pklen Length of the binary data.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_symmetric_key_hex_from_bin(struct cpn_symmetric_key_hex *out, const uint8_t *data, size_t datalen);

/** @brief Convert symmetric key into hex representation
 *
 * @param[out] out Pointer to store symmetric hex
 *             representation at.
 * @param[in] key Public signature key to convert.
 */
void cpn_symmetric_key_hex_from_key(struct cpn_symmetric_key_hex *out, const struct cpn_symmetric_key *key);

/** @brief Increment nonce by `count` */
void cpn_symmetric_key_nonce_increment(struct cpn_symmetric_key_nonce *nonce, size_t count);

#endif

/** @} */
