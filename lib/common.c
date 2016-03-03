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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/channel.h"
#include "lib/cfg.h"
#include "lib/log.h"

#include "common.h"

#include "proto/encryption.pb-c.h"

int spawn(thread_fn fn, void *payload)
{
    int pid = fork();

    if (pid == 0) {
        /* child */
        fn(payload);
        exit(0);
    } else if (pid > 0) {
        /* parent */
        return pid;
    } else {
        printf("Could not spawn function: %s\n", strerror(errno));
        return -1;
    }
}

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

int receive_session_key(struct sd_channel *channel,
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

int initiate_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_sign_key_public *remote_sign_key)
{
    struct sd_encrypt_key_pair local_keys;
    struct sd_encrypt_key_public received_encrypt_key;
    struct sd_sign_key_public received_sign_key;
    struct sd_symmetric_key shared_key;
    uint8_t local_nonce[crypto_box_NONCEBYTES],
            remote_nonce[crypto_box_NONCEBYTES],
            scalarmult[crypto_scalarmult_BYTES];
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

    memset(local_nonce, 0, sizeof(local_nonce));
    memset(remote_nonce, 0, sizeof(remote_nonce));
    sodium_increment(remote_nonce, sizeof(remote_nonce));

    if (sd_channel_set_crypto_symmetric(channel, &shared_key, local_nonce, remote_nonce) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}

int await_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        struct sd_sign_key_public *remote_sign_key)
{
    struct sd_encrypt_key_pair local_keys;
    struct sd_encrypt_key_public remote_key;
    struct sd_symmetric_key shared_key;
    uint8_t local_nonce[crypto_box_NONCEBYTES],
            remote_nonce[crypto_box_NONCEBYTES],
            scalarmult[crypto_scalarmult_BYTES];
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

    memset(local_nonce, 0, sizeof(local_nonce));
    sodium_increment(local_nonce, sizeof(local_nonce));
    memset(remote_nonce, 0, sizeof(remote_nonce));

    if (sd_channel_set_crypto_symmetric(channel, &shared_key, local_nonce, remote_nonce) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}
