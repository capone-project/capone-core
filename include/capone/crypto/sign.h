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

#ifndef CPN_LIB_CRYPTO_SIGN_H
#define CPN_LIB_CRYPTO_SIGN_H

#include <stdlib.h>
#include <inttypes.h>

#include "capone/cfg.h"
#include "capone/proto/core.pb-c.h"

#define CPN_CRYPTO_SIGN_SKBYTES 64
#define CPN_CRYPTO_SIGN_PKBYTES 32
#define CPN_CRYPTO_SIGN_SIGBYTES 64

/** @brief Secret signature key used to sign data */
struct cpn_sign_sk {
    uint8_t data[CPN_CRYPTO_SIGN_SKBYTES];
};

/** @brief Public signature key used to verify data */
struct cpn_sign_pk {
    uint8_t data[CPN_CRYPTO_SIGN_PKBYTES];
};

/** @brief Signature key pair */
struct cpn_sign_keys {
    struct cpn_sign_sk sk;
    struct cpn_sign_pk pk;
};

struct cpn_sign_sig {
    uint8_t data[CPN_CRYPTO_SIGN_SIGBYTES];
};

/** @brief Hex representation of a public signature key */
struct cpn_sign_pk_hex {
    char data[CPN_CRYPTO_SIGN_PKBYTES * 2 + 1];
};

/** @brief Generate a new signature key pair
 *
 * @param[out] out Pointer to store key pair at.
 * @return <code>0</code>
 */
int cpn_sign_keys_generate(struct cpn_sign_keys *out);

/** @brief Read a public signature key from binary data
 *
 * @param[out] out Pointer to store public signature key at.
 * @param[in] pk Binary representation of the key.
 * @param[in] pklen Length of the binary data.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_sign_pk_from_bin(struct cpn_sign_pk *out, const uint8_t *pk, size_t pklen);

/** @brief Read a public signature key from hex
 *
 * @param[out] out Pointer to store public signature key at.
 * @param[in] hex Hex representation of the key.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_sign_pk_from_hex(struct cpn_sign_pk *out, const char *hex);

/** @brief Convert an IdentityMessage to a signature key
 *
 * @param[out] out Public signature key derived from the message
 * @param[in] msg Message to derive public key from
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_sign_pk_from_proto(struct cpn_sign_pk *out, const IdentityMessage *msg);

/** @brief Convert a public signature key to a protobufmessage
 *
 * @param[out] out Newly allocated protobuf message
 * @param[in] key Key to convert
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_sign_pk_to_proto(IdentityMessage **out, const struct cpn_sign_pk *key);

/** @brief Read a public signature key hex representation from binary data
 *
 * @param[out] out Pointer to store public signature hex
 *             representation at.
 * @param[in] pk Binary representation of the key.
 * @param[in] pklen Length of the binary data.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_sign_pk_hex_from_bin(struct cpn_sign_pk_hex *out, const uint8_t *pk, size_t pklen);

/** @brief Convert public signature key into hex representation
 *
 * @param[out] out Pointer to store public signature hex
 *             representation at.
 * @param[in] key Public signature key to convert.
 */
void cpn_sign_pk_hex_from_key(struct cpn_sign_pk_hex *out, const struct cpn_sign_pk *key);

/** @brief Read a signature key pair from a configuration
 *
 * Read a key pair from a configuration. The key pair is assumed
 * to be present in the "core" section and stored in the entries
 * "public_key" and "secret_key".
 *
 * @param[out] out Pointer to store key pair at.
 * @param[in] cfg Configuration to read keys from.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_sign_keys_from_config(struct cpn_sign_keys *out, const struct cpn_cfg *cfg);

/** @brief Read a signature key pair from a configuration file
 *
 * Read a key pair from a configuration file.
 *
 * @param[out] out Pointer to store key pair at.
 * @param[in] file Path of the configuration file.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_sign_keys_from_config
 */
int cpn_sign_keys_from_config_file(struct cpn_sign_keys *out, const char *file);

/** @brief Create a signature from its binary representation */
int cpn_sign_sig_from_bin(struct cpn_sign_sig *out, const uint8_t *data, size_t datalen);

/** @brief Create a signature for given data */
int cpn_sign_sig(struct cpn_sign_sig *out, const struct cpn_sign_sk *key,
        uint8_t *data, size_t datalen);

/** @brief Verify a signature for given data */
int cpn_sign_sig_verify(const struct cpn_sign_pk *key, const struct cpn_sign_sig *sig,
        uint8_t *data, size_t datalen);

#endif
