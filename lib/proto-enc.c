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

#include "lib/channel.h"
#include "lib/log.h"

#include "proto/encryption.pb-c.h"

static int send_ephemeral_key(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_encrypt_key_public *encrypt_key)
{
    uint8_t signature[crypto_sign_BYTES],
            sign_data[crypto_sign_PUBLICKEYBYTES + crypto_box_PUBLICKEYBYTES];
    SignedKey msg = SIGNED_KEY__INIT;

    memcpy(sign_data, sign_keys->pk.data, sizeof(sign_keys->pk.data));
    memcpy(sign_data + sizeof(sign_keys->pk.data), encrypt_key->data, sizeof(encrypt_key->data));

    /* We may end up sending more bytes than the signature is
     * long. To avoid a buffer overflow on the other side, always
     * send the maximum signature length and set the trailing
     * bytes to zero*/
    memset(signature, 0, sizeof(signature));
    if (crypto_sign_detached(signature, NULL, sign_data, sizeof(sign_data),
                sign_keys->sk.data) != 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to sign generated key");
        return -1;
    }

    msg.sign_pk.data = (uint8_t *) sign_keys->pk.data;
    msg.sign_pk.len = sizeof(sign_keys->pk.data);
    msg.encrypt_pk.data = (uint8_t *) encrypt_key->data;
    msg.encrypt_pk.len = sizeof(encrypt_key->data);
    msg.signature.data = signature;
    msg.signature.len = sizeof(signature);

    if (sd_channel_write_protobuf(channel, &msg.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not send negotiation");
        return -1;
    }

    return 0;
}

static int receive_session_key(
        struct sd_channel *channel,
        struct sd_sign_key_public *remote_sign_key,
        struct sd_encrypt_key_public *remote_encrypt_key)
{
    SignedKey *msg;
    uint8_t sign_data[crypto_sign_PUBLICKEYBYTES + crypto_box_PUBLICKEYBYTES];

    if (sd_channel_receive_protobuf(channel,
                &signed_key__descriptor,
                (ProtobufCMessage **) &msg) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Failed receiving negotiation response");
        return -1;
    }

    if (msg->signature.len != crypto_sign_BYTES) {
        sd_log(LOG_LEVEL_ERROR, "Received signature length does not match");
        return -1;
    } else if (msg->sign_pk.len != crypto_sign_PUBLICKEYBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Received signing key length does not match");
        return -1;
    } else if (msg->encrypt_pk.len != crypto_box_PUBLICKEYBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Received ephemeral key length does not match");
        return -1;
    }

    memcpy(sign_data, msg->sign_pk.data, msg->sign_pk.len);
    memcpy(sign_data + msg->sign_pk.len, msg->encrypt_pk.data, msg->encrypt_pk.len);

    if (crypto_sign_verify_detached(msg->signature.data,
                sign_data, sizeof(sign_data), msg->sign_pk.data) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Received key not signed correctly");
        return -1;
    }

    if (sd_sign_key_public_from_bin(remote_sign_key,
                msg->sign_pk.data, msg->sign_pk.len) < 0 ||
            sd_encrypt_key_public_from_bin(remote_encrypt_key,
                msg->encrypt_pk.data, msg->encrypt_pk.len) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Invalid keys");
        return -1;
    }

    signed_key__free_unpacked(msg, NULL);

    return 0;
}

static int send_signed_key(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_encrypt_key_public *local_emph_key,
        const struct sd_encrypt_key_public *remote_emph_key)
{
    SignedKeys msg = SIGNED_KEYS__INIT;
    uint8_t signature[crypto_sign_BYTES],
            sign_data[crypto_box_PUBLICKEYBYTES * 2];

    memcpy(sign_data, local_emph_key->data, crypto_box_PUBLICKEYBYTES);
    memcpy(sign_data + crypto_box_PUBLICKEYBYTES, remote_emph_key->data, crypto_box_PUBLICKEYBYTES);

    memset(signature, 0, sizeof(signature));
    if (crypto_sign_detached(signature, NULL, sign_data, sizeof(sign_data),
                sign_keys->sk.data) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to sign ephemeral key");
        return -1;
    }

    msg.sender_pk.data = (uint8_t *) local_emph_key->data;
    msg.sender_pk.len = sizeof(local_emph_key->data);
    msg.receiver_pk.data = (uint8_t *) remote_emph_key->data;
    msg.receiver_pk.len = sizeof(remote_emph_key->data);
    msg.signature.data = signature;
    msg.signature.len = sizeof(signature);

    if (sd_channel_write_protobuf(channel, &msg.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Received invalid ephemeral key signature");
        return -1;
    }

    return 0;
}

static int receive_signed_key(struct sd_encrypt_key_public *out,
        struct sd_channel *channel,
        const struct sd_encrypt_key_public *local_emph_key,
        const struct sd_sign_key_public *remote_sign_key)
{
    SignedKeys *msg;
    uint8_t sign_data[crypto_box_PUBLICKEYBYTES * 2];

    if (sd_channel_receive_protobuf(channel,
            &signed_keys__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        goto out_err;
    }

    /* Check lengths */
    if (msg->signature.len != crypto_sign_BYTES) {
        sd_log(LOG_LEVEL_ERROR, "Received signature's length does not match");
        goto out_err;
    } else if (msg->sender_pk.len != crypto_box_PUBLICKEYBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Received sender's PKlength does not match");
        goto out_err;
    } else if (msg->receiver_pk.len != crypto_box_PUBLICKEYBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Received receiver's PK length does not match");
        goto out_err;
    }

    /* Check if local ephemeral key matches */
    if (memcmp(local_emph_key->data, msg->receiver_pk.data, crypto_box_PUBLICKEYBYTES)) {
        sd_log(LOG_LEVEL_ERROR, "Unexpected receiver PK");
        goto out_err;
    }

    memcpy(sign_data, msg->sender_pk.data, crypto_box_PUBLICKEYBYTES);
    memcpy(sign_data + crypto_box_PUBLICKEYBYTES, msg->receiver_pk.data, crypto_box_PUBLICKEYBYTES);
    if (crypto_sign_verify_detached(msg->signature.data, sign_data, sizeof(sign_data), remote_sign_key->data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Received invalid signature");
        goto out_err;
    }

    if (out) {
        memcpy(&out->data, msg->sender_pk.data, sizeof(out->data));
    }

    signed_keys__free_unpacked(msg, NULL);
    return 0;

out_err:
    signed_keys__free_unpacked(msg, NULL);
    return -1;
}

int sd_proto_initiate_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_sign_key_public *remote_sign_key)
{
    struct sd_encrypt_key_pair emph_keys;
    struct sd_encrypt_key_public remote_emph_key;
    struct sd_symmetric_key shared_key;
    uint8_t scalarmult[crypto_scalarmult_BYTES];
    crypto_generichash_state hash;

    if (sd_encrypt_key_pair_generate(&emph_keys) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    if (send_ephemeral_key(channel, sign_keys, &emph_keys.pk) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send session key");
        return -1;
    }

    if (receive_signed_key(&remote_emph_key, channel, &emph_keys.pk, remote_sign_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        return -1;
    }

    if (send_signed_key(channel, sign_keys, &emph_keys.pk, &remote_emph_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send ephemeral key signature");
        return -1;
    }

    if (crypto_scalarmult(scalarmult, emph_keys.sk.data, remote_emph_key.data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to perform scalarmultiplication");
        return -1;
    }

    if (crypto_generichash_init(&hash, NULL, 0, sizeof(shared_key.data)) < 0 ||
            crypto_generichash_update(&hash, scalarmult, sizeof(scalarmult)) < 0 ||
            crypto_generichash_update(&hash, emph_keys.pk.data, sizeof(emph_keys.pk.data)) < 0 ||
            crypto_generichash_update(&hash, remote_emph_key.data, sizeof(remote_emph_key.data)) < 0 ||
            crypto_generichash_final(&hash, shared_key.data, sizeof(shared_key.data)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to calculate h(q || pk1 || pk2)");
        return -1;
    }

    sodium_memzero(&emph_keys, sizeof(emph_keys));

    if (sd_channel_enable_encryption(channel, &shared_key, 0) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}

int sd_proto_await_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        struct sd_sign_key_public *remote_sign_key)
{
    struct sd_encrypt_key_pair emph_keys;
    struct sd_encrypt_key_public remote_emph_key;
    struct sd_symmetric_key shared_key;
    uint8_t scalarmult[crypto_scalarmult_BYTES];
    crypto_generichash_state hash;

    if (receive_session_key(channel, remote_sign_key, &remote_emph_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive session key");
        return -1;
    }

    if (sd_encrypt_key_pair_generate(&emph_keys) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    if (send_signed_key(channel, sign_keys, &emph_keys.pk, &remote_emph_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send ephemeral key signature");
        return -1;
    }

    if (receive_signed_key(NULL, channel, &emph_keys.pk, remote_sign_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        return -1;
    }

    if (crypto_scalarmult(scalarmult, emph_keys.sk.data, remote_emph_key.data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to perform scalarmultiplication");
        return -1;
    }

    if (crypto_generichash_init(&hash, NULL, 0, sizeof(shared_key.data)) < 0 ||
            crypto_generichash_update(&hash, scalarmult, sizeof(scalarmult)) < 0 ||
            crypto_generichash_update(&hash, remote_emph_key.data, sizeof(remote_emph_key.data)) < 0 ||
            crypto_generichash_update(&hash, emph_keys.pk.data, sizeof(emph_keys.pk.data)) < 0 ||
            crypto_generichash_final(&hash, shared_key.data, sizeof(shared_key.data)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to calculate h(q || pk1 || pk2)");
        return -1;
    }

    sodium_memzero(&emph_keys, sizeof(emph_keys));

    if (sd_channel_enable_encryption(channel, &shared_key, 1) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}
