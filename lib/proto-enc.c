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

#include "capone/buf.h"
#include "capone/channel.h"
#include "capone/log.h"

#include "capone/proto/encryption.pb-c.h"

static int send_ephemeral_key(struct cpn_channel *channel,
        uint32_t id,
        const struct cpn_sign_key_pair *sign_keys,
        const struct cpn_encrypt_key_public *encrypt_key)
{
    InitiatorKey msg = INITIATOR_KEY__INIT;

    msg.sign_pk.data = (uint8_t *) sign_keys->pk.data;
    msg.sign_pk.len = sizeof(sign_keys->pk.data);
    msg.ephm_pk.data = (uint8_t *) encrypt_key->data;
    msg.ephm_pk.len = sizeof(encrypt_key->data);
    msg.sessionid = id;

    if (cpn_channel_write_protobuf(channel, &msg.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send negotiation");
        return -1;
    }

    return 0;
}

static int receive_ephemeral_key(
        struct cpn_channel *channel,
        uint32_t *id,
        struct cpn_sign_key_public *remote_sign_key,
        struct cpn_encrypt_key_public *remote_encrypt_key)
{
    InitiatorKey *msg;

    if (cpn_channel_receive_protobuf(channel,
                &initiator_key__descriptor,
                (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Failed receiving negotiation response");
        return -1;
    }

    if (cpn_sign_key_public_from_bin(remote_sign_key,
                msg->sign_pk.data, msg->sign_pk.len) < 0 ||
            cpn_encrypt_key_public_from_bin(remote_encrypt_key,
                msg->ephm_pk.data, msg->ephm_pk.len) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Invalid keys");
        return -1;
    }

    *id = msg->sessionid;

    initiator_key__free_unpacked(msg, NULL);

    return 0;
}

static void fill_sign_buffer(struct cpn_buf *buf,
        uint32_t id,
        const struct cpn_sign_key_public *s1,
        const struct cpn_sign_key_public *s2,
        const struct cpn_encrypt_key_public *e1,
        const struct cpn_encrypt_key_public *e2)
{
    cpn_buf_append_data(buf, s1->data, crypto_sign_PUBLICKEYBYTES);
    cpn_buf_append_data(buf, (unsigned char *) &id, sizeof(id));
    cpn_buf_append_data(buf, e1->data, crypto_box_PUBLICKEYBYTES);
    cpn_buf_append_data(buf, e2->data, crypto_box_PUBLICKEYBYTES);
    cpn_buf_append_data(buf, s2->data, crypto_box_PUBLICKEYBYTES);
}

static int send_signed_key(struct cpn_channel *channel,
        uint32_t id,
        const struct cpn_sign_key_pair *sign_keys,
        const struct cpn_encrypt_key_public *local_emph_key,
        const struct cpn_sign_key_public *remote_sign_key,
        const struct cpn_encrypt_key_public *remote_emph_key)
{
    ResponderKey msg = RESPONDER_KEY__INIT;
    uint8_t signature[crypto_sign_BYTES];
    struct cpn_buf sign_buf = CPN_BUF_INIT;
    int err = 0;

    fill_sign_buffer(&sign_buf, id,
            &sign_keys->pk, remote_sign_key,
            local_emph_key, remote_emph_key);

    memset(signature, 0, sizeof(signature));
    if ((err = crypto_sign_detached(signature, NULL,
                    (unsigned char *) sign_buf.data, sign_buf.length,
                    sign_keys->sk.data)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to sign ephemeral key");
        goto out;
    }

    msg.sessionid = id;
    msg.sign_pk.data = (uint8_t *) sign_keys->pk.data;
    msg.sign_pk.len = sizeof(sign_keys->pk.data);
    msg.ephm_pk.data = (uint8_t *) local_emph_key->data;
    msg.ephm_pk.len = sizeof(local_emph_key->data);
    msg.signature.data = signature;
    msg.signature.len = sizeof(signature);

    if ((err = cpn_channel_write_protobuf(channel, &msg.base)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid ephemeral key signature");
        goto out;
    }

out:
    cpn_buf_clear(&sign_buf);

    return 0;
}

static int receive_signed_key(struct cpn_encrypt_key_public *out,
        struct cpn_channel *channel,
        uint32_t id,
        const struct cpn_sign_key_public *local_sign_key,
        const struct cpn_encrypt_key_public *local_emph_key,
        const struct cpn_sign_key_public *remote_sign_key)
{
    ResponderKey *msg;
    struct cpn_buf sign_buf = CPN_BUF_INIT;
    struct cpn_sign_key_public msg_sign_key;
    struct cpn_encrypt_key_public msg_emph_key;
    int ret = -1;

    if (cpn_channel_receive_protobuf(channel,
            &responder_key__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        goto out;
    }

    /* Verify parameters */
    if (msg->sessionid != id) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid session id");
        goto out;
    } else if (msg->signature.len != crypto_sign_BYTES) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid signature");
        goto out;
    } else if (cpn_sign_key_public_from_bin(&msg_sign_key, msg->sign_pk.data, msg->sign_pk.len) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Initiator's long-term signature key is invalid");
        goto out;
    } else if (cpn_encrypt_key_public_from_bin(&msg_emph_key, msg->ephm_pk.data, msg->ephm_pk.len) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Initiator's ephemeral key is invalid");
        goto out;
    }

    if (memcmp(&msg_sign_key, remote_sign_key, sizeof(msg_sign_key))) {
        cpn_log(LOG_LEVEL_ERROR, "Received unexpected sign key");
        goto out;
    }

    fill_sign_buffer(&sign_buf, id,
            &msg_sign_key, local_sign_key,
            &msg_emph_key, local_emph_key);

    if (crypto_sign_verify_detached(msg->signature.data,
                (unsigned char *) sign_buf.data, sign_buf.length,
                remote_sign_key->data) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid signature");
        goto out;
    }

    if (out) {
        memcpy(out, &msg_emph_key, sizeof(msg_emph_key));
    }

    ret = 0;

out:
    cpn_buf_clear(&sign_buf);
    if (msg)
        responder_key__free_unpacked(msg, NULL);

    return ret;
}

static int send_key_verification(struct cpn_channel *c,
        uint32_t id,
        const struct cpn_sign_key_pair *sign_keys,
        const struct cpn_encrypt_key_public *local_emph_key,
        const struct cpn_sign_key_public *remote_pk,
        const struct cpn_encrypt_key_public *remote_emph_pk)
{
    AcknowledgeKey msg = ACKNOWLEDGE_KEY__INIT;
    struct cpn_buf sign_buf = CPN_BUF_INIT;
    uint8_t signature[crypto_sign_BYTES], *sign_data = NULL;
    int err = 0;

    fill_sign_buffer(&sign_buf, id,
            &sign_keys->pk, remote_pk,
            local_emph_key, remote_emph_pk);

    memset(signature, 0, sizeof(signature));
    if ((err = crypto_sign_detached(signature, NULL,
                    (unsigned char *) sign_buf.data, sign_buf.length,
                    sign_keys->sk.data)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to sign key verification");
        goto out;
    }

    msg.sessionid = id;
    msg.sign_pk.data = (uint8_t *) sign_keys->pk.data;
    msg.sign_pk.len = sizeof(sign_keys->pk.data);
    msg.signature.data = signature;
    msg.signature.len = sizeof(signature);

    if (cpn_channel_write_protobuf(c, &msg.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send verification message");
        return -1;
    }

out:
    free(sign_data);

    return err;
}

static int receive_key_verification(struct cpn_channel *c,
        uint32_t id,
        const struct cpn_sign_key_public *local_pk,
        const struct cpn_encrypt_key_public *local_emph_key,
        const struct cpn_sign_key_public *remote_pk,
        const struct cpn_encrypt_key_public *remote_emph_key)
{
    AcknowledgeKey *msg = NULL;
    struct cpn_buf sign_buf = CPN_BUF_INIT;
    uint8_t *sign_data = NULL;
    int err = -1;

    if (cpn_channel_receive_protobuf(c,
            &acknowledge_key__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive acknowledge message");
        goto out;
    }

    if (msg->sessionid != id) {
        cpn_log(LOG_LEVEL_ERROR, "Verification has invalid session");
        goto out;
    } else if (msg->sign_pk.len != sizeof(remote_pk->data) ||
            memcmp(msg->sign_pk.data, remote_pk->data, msg->sign_pk.len)) {
        cpn_log(LOG_LEVEL_ERROR, "Verification key does not match");
        goto out;
    } else if (msg->signature.len != crypto_sign_BYTES) {
        cpn_log(LOG_LEVEL_ERROR, "Verification has invalid signature length");
        goto out;
    }

    fill_sign_buffer(&sign_buf, id,
            remote_pk, local_pk, remote_emph_key, local_emph_key);

    if (crypto_sign_verify_detached(msg->signature.data,
                (unsigned char *) sign_buf.data, sign_buf.length,
                remote_pk->data) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid signature");
        goto out;
    }

    err = 0;

out:
    free(sign_data);
    if (msg)
        acknowledge_key__free_unpacked(msg, NULL);

    return err;
}

int cpn_proto_initiate_encryption(struct cpn_channel *channel,
        const struct cpn_sign_key_pair *sign_keys,
        const struct cpn_sign_key_public *remote_sign_key)
{
    struct cpn_encrypt_key_pair emph_keys;
    struct cpn_encrypt_key_public remote_emph_key;
    struct cpn_symmetric_key shared_key;
    uint8_t scalarmult[crypto_scalarmult_BYTES];
    crypto_generichash_state hash;
    uint32_t id;

    if (cpn_encrypt_key_pair_generate(&emph_keys) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    id = randombytes_random();

    if (send_ephemeral_key(channel, id, sign_keys, &emph_keys.pk) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send session key");
        return -1;
    }

    if (receive_signed_key(&remote_emph_key, channel, id,
                &sign_keys->pk, &emph_keys.pk, remote_sign_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        return -1;
    }

    if (send_key_verification(channel, id,
                sign_keys, &emph_keys.pk,
                remote_sign_key, &remote_emph_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send key verification");
        return -1;
    }

    if (crypto_scalarmult(scalarmult, emph_keys.sk.data, remote_emph_key.data) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to perform scalarmultiplication");
        return -1;
    }

    if (crypto_generichash_init(&hash, NULL, 0, sizeof(shared_key.data)) < 0 ||
            crypto_generichash_update(&hash, scalarmult, sizeof(scalarmult)) < 0 ||
            crypto_generichash_update(&hash, emph_keys.pk.data, sizeof(emph_keys.pk.data)) < 0 ||
            crypto_generichash_update(&hash, remote_emph_key.data, sizeof(remote_emph_key.data)) < 0 ||
            crypto_generichash_final(&hash, shared_key.data, sizeof(shared_key.data)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to calculate h(q || pk1 || pk2)");
        return -1;
    }

    sodium_memzero(&emph_keys, sizeof(emph_keys));

    if (cpn_channel_enable_encryption(channel, &shared_key, 0) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}

int cpn_proto_await_encryption(struct cpn_channel *channel,
        const struct cpn_sign_key_pair *sign_keys,
        struct cpn_sign_key_public *remote_sign_key)
{
    struct cpn_encrypt_key_pair emph_keys;
    struct cpn_encrypt_key_public remote_emph_key;
    struct cpn_symmetric_key shared_key;
    uint8_t scalarmult[crypto_scalarmult_BYTES];
    uint32_t id;
    crypto_generichash_state hash;

    if (receive_ephemeral_key(channel, &id, remote_sign_key, &remote_emph_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive session key");
        return -1;
    }

    if (cpn_encrypt_key_pair_generate(&emph_keys) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    if (send_signed_key(channel, id,
                sign_keys, &emph_keys.pk,
                remote_sign_key, &remote_emph_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send ephemeral key signature");
        return -1;
    }

    if (receive_key_verification(channel, id,
                &sign_keys->pk, &emph_keys.pk,
                remote_sign_key, &remote_emph_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive verification");
        return -1;
    }

    if (crypto_scalarmult(scalarmult, emph_keys.sk.data, remote_emph_key.data) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to perform scalarmultiplication");
        return -1;
    }

    if (crypto_generichash_init(&hash, NULL, 0, sizeof(shared_key.data)) < 0 ||
            crypto_generichash_update(&hash, scalarmult, sizeof(scalarmult)) < 0 ||
            crypto_generichash_update(&hash, remote_emph_key.data, sizeof(remote_emph_key.data)) < 0 ||
            crypto_generichash_update(&hash, emph_keys.pk.data, sizeof(emph_keys.pk.data)) < 0 ||
            crypto_generichash_final(&hash, shared_key.data, sizeof(shared_key.data)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to calculate h(q || pk1 || pk2)");
        return -1;
    }

    sodium_memzero(&emph_keys, sizeof(emph_keys));

    if (cpn_channel_enable_encryption(channel, &shared_key, 1) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}
