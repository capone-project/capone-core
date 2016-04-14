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

static int send_session_key(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_encrypt_key_public *encrypt_key)
{
    uint8_t signature[crypto_sign_BYTES];
    SessionKeyMessage env = SESSION_KEY_MESSAGE__INIT;

    /* We may end up sending more bytes than the signature is
     * long. To avoid a buffer overflow on the other side, always
     * send the maximum signature length and set the trailing
     * bytes to zero*/
    memset(signature, 0, sizeof(signature));
    if (crypto_sign_detached(signature, NULL,
                encrypt_key->data, sizeof(encrypt_key->data), sign_keys->sk.data) != 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to sign generated key");
        return -1;
    }

    env.sign_pk.data = (uint8_t *) sign_keys->pk.data;
    env.sign_pk.len = sizeof(sign_keys->pk.data);
    env.encrypt_pk.data = (uint8_t *) encrypt_key->data;
    env.encrypt_pk.len = sizeof(encrypt_key->data);
    env.signature.data = signature;
    env.signature.len = sizeof(signature);

    if (sd_channel_write_protobuf(channel, &env.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not send negotiation");
        return -1;
    }

    return 0;
}

static int receive_session_key(struct sd_channel *channel,
        struct sd_sign_key_public *remote_sign_key,
        struct sd_encrypt_key_public *remote_encrypt_key)
{
    SessionKeyMessage *response;

    if (sd_channel_receive_protobuf(channel,
                &session_key_message__descriptor, (ProtobufCMessage **) &response) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Failed receiving negotiation response");
        return -1;
    }

    if (response->sign_pk.len != crypto_sign_PUBLICKEYBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Received signing key length does not match");
        return -1;
    }

    if (crypto_sign_verify_detached(response->signature.data,
                response->encrypt_pk.data, response->encrypt_pk.len, response->sign_pk.data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Received key not signed correctly");
        return -1;
    }

    if (remote_sign_key) {
        memcpy(remote_sign_key->data, response->sign_pk.data, sizeof(remote_sign_key->data));
    }

    if (sd_encrypt_key_public_from_bin(remote_encrypt_key,
                response->encrypt_pk.data, response->encrypt_pk.len) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not retrieve remote public key");
        return -1;
    }

    session_key_message__free_unpacked(response, NULL);

    return 0;
}

static int send_key_signature(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_symmetric_key *ephemeral_key)
{
    uint8_t signature[crypto_sign_BYTES];
    EphemeralKeySignatureMessage msg = EPHEMERAL_KEY_SIGNATURE_MESSAGE__INIT;

    if (crypto_sign_detached(signature, NULL,
            ephemeral_key->data, sizeof(ephemeral_key->data),
            sign_keys->sk.data) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to sign ephemeral key");
        return -1;
    }

    msg.signature.data = signature;
    msg.signature.len = sizeof(signature);

    if (sd_channel_write_protobuf(channel, &msg.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Received invalid ephemeral key signature");
        return -1;
    }

    return 0;
}

static int receive_key_signature(struct sd_channel *channel,
        const struct sd_sign_key_public *verify_key,
        const struct sd_symmetric_key *ephemeral_key)
{
    EphemeralKeySignatureMessage *msg = NULL;

    if (sd_channel_receive_protobuf(channel,
            &ephemeral_key_signature_message__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        goto out_err;
    }

    if (msg->signature.len != crypto_sign_BYTES) {
        sd_log(LOG_LEVEL_ERROR, "Received signature's length does not match");
        goto out_err;
    }

    if (crypto_sign_verify_detached(msg->signature.data, ephemeral_key->data,
                sizeof(ephemeral_key->data), verify_key->data) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Ephemeral key signature is invalid");
        goto out_err;
    }

    return 0;

out_err:
    ephemeral_key_signature_message__free_unpacked(msg, NULL);
    return -1;
}

int sd_proto_initiate_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_sign_key_public *remote_sign_key)
{
    struct sd_encrypt_key_pair local_keys;
    struct sd_encrypt_key_public received_encrypt_key;
    struct sd_sign_key_public received_sign_key;
    struct sd_symmetric_key shared_key;
    uint8_t scalarmult[crypto_scalarmult_BYTES];
    crypto_generichash_state hash;

    if (sd_encrypt_key_pair_generate(&local_keys) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    if (send_session_key(channel, sign_keys, &local_keys.pk) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send session key");
        return -1;
    }

    if (receive_session_key(channel, &received_sign_key, &received_encrypt_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive session key");
        return -1;
    }

    if (memcmp(received_sign_key.data, remote_sign_key->data, sizeof(received_sign_key.data))) {
        sd_log(LOG_LEVEL_ERROR, "Signature key does not match expected key");
        return -1;
    }

    if (crypto_scalarmult(scalarmult, local_keys.sk.data, received_encrypt_key.data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to perform scalarmultiplication");
        return -1;
    }

    if (crypto_generichash_init(&hash, NULL, 0, sizeof(shared_key.data)) < 0 ||
            crypto_generichash_update(&hash, scalarmult, sizeof(scalarmult)) < 0 ||
            crypto_generichash_update(&hash, local_keys.pk.data, sizeof(local_keys.pk.data)) < 0 ||
            crypto_generichash_update(&hash, received_encrypt_key.data, sizeof(received_encrypt_key.data)) < 0 ||
            crypto_generichash_final(&hash, shared_key.data, sizeof(shared_key.data)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to calculate h(q || pk1 || pk2)");
        return -1;
    }

    sodium_memzero(&local_keys, sizeof(local_keys));

    if (send_key_signature(channel, sign_keys, &shared_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send ephemeral key signature");
        return -1;
    }

    if (receive_key_signature(channel, remote_sign_key, &shared_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        return -1;
    }

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
    struct sd_encrypt_key_pair local_keys;
    struct sd_encrypt_key_public remote_key;
    struct sd_symmetric_key shared_key;
    uint8_t scalarmult[crypto_scalarmult_BYTES];
    crypto_generichash_state hash;

    if (sd_encrypt_key_pair_generate(&local_keys) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    if (receive_session_key(channel, remote_sign_key, &remote_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive session key");
        return -1;
    }

    if (send_session_key(channel, sign_keys, &local_keys.pk) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send session key");
        return -1;
    }

    if (crypto_scalarmult(scalarmult, local_keys.sk.data, remote_key.data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to perform scalarmultiplication");
        return -1;
    }

    if (crypto_generichash_init(&hash, NULL, 0, sizeof(shared_key.data)) < 0 ||
            crypto_generichash_update(&hash, scalarmult, sizeof(scalarmult)) < 0 ||
            crypto_generichash_update(&hash, remote_key.data, sizeof(remote_key.data)) < 0 ||
            crypto_generichash_update(&hash, local_keys.pk.data, sizeof(local_keys.pk.data)) < 0 ||
            crypto_generichash_final(&hash, shared_key.data, sizeof(shared_key.data)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to calculate h(q || pk1 || pk2)");
        return -1;
    }

    sodium_memzero(&local_keys, sizeof(local_keys));

    if (send_key_signature(channel, sign_keys, &shared_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send ephemeral key signature");
        return -1;
    }

    if (receive_key_signature(channel, remote_sign_key, &shared_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        return -1;
    }

    if (sd_channel_enable_encryption(channel, &shared_key, 1) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}
