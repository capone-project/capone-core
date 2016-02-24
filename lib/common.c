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

#include "proto/encryption.pb-c.h"

#include "common.h"

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

int pack_signed_protobuf(Envelope **out, const ProtobufCMessage *msg,
        const struct sd_key_pair *keys, const struct sd_key_public *remote_key)
{
    Envelope *env;
    uint8_t mac[crypto_sign_BYTES];
    uint8_t *buf = NULL;
    int len;
    unsigned long long maclen;

    *out = NULL;

    if (!protobuf_c_message_check(msg)) {
        sd_log(LOG_LEVEL_ERROR, "Can not pack invalid protobuf");
        return -1;
    }

    len = protobuf_c_message_get_packed_size(msg);
    buf = malloc(len);
    protobuf_c_message_pack(msg, buf);

    env = malloc(sizeof(Envelope));
    envelope__init(env);

    if (crypto_sign_detached(mac, &maclen, buf, len, keys->sk.sign) != 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to sign protobuf");
        goto out_err;
    }
    env->mac.data = malloc(maclen);
    memcpy(env->mac.data, mac, maclen);
    env->mac.len = maclen;

    if (remote_key) {
        uint8_t *ciphertext = malloc(len + crypto_box_SEALBYTES);

        if (crypto_box_seal(ciphertext, buf, len, remote_key->box) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Unable to encrypt protobuf");
            goto out_err;
        }

        free(buf);
        buf = ciphertext;
        len = len + crypto_box_SEALBYTES;
        env->encrypted = 1;
    } else {
        env->encrypted = 0;
    }
    env->data.data = buf;
    env->data.len = len;

    env->pk.data = malloc(sizeof(keys->pk.sign));
    memcpy(env->pk.data, keys->pk.sign, sizeof(keys->pk.sign));
    env->pk.len = sizeof(keys->pk.sign);

    *out = env;

    return 0;

out_err:
    envelope__free_unpacked(env, NULL);
    free(buf);

    return -1;
}

int unpack_signed_protobuf(const ProtobufCMessageDescriptor *descr,
        ProtobufCMessage **out, const Envelope *env, const struct sd_key_pair *keys)
{
    ProtobufCMessage *msg;
    uint8_t *data;
    size_t len;

    *out = NULL;

    if (env->mac.len != crypto_sign_BYTES) {
        sd_log(LOG_LEVEL_ERROR, "Invalid MAC length");
        return -1;
    }
    if (env->pk.len != crypto_sign_ed25519_PUBLICKEYBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Invalid public key length");
        return -1;
    }

    if (env->encrypted) {
        if (env->data.len <= crypto_box_SEALBYTES) {
            sd_log(LOG_LEVEL_ERROR, "Invalid cipherext length");
            return -1;
        }

        data = malloc(env->data.len - crypto_box_SEALBYTES);
        len = env->data.len - crypto_box_SEALBYTES;

        if (crypto_box_seal_open(data, env->data.data, env->data.len,
                keys->pk.box, keys->sk.box) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Unable to decrypt protobuf");
            return -1;
        }
    } else {
        data = env->data.data;
        len = env->data.len;
    }

    if (crypto_sign_verify_detached(env->mac.data, data, len, env->pk.data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to verify signed protobuf");
        return -1;
    }

    msg = protobuf_c_message_unpack(descr, NULL, len, data);
    if (msg == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Unable to unpack signed protobuf");
        return -1;
    }
    if (env->encrypted)
        free(data);

    *out = msg;

    return 0;
}

int initiate_encryption(struct sd_channel *channel,
        const struct sd_key_pair *local_keys,
        const struct sd_key_public *remote_keys)
{
    uint8_t nonce[crypto_box_NONCEBYTES];
    EncryptionNegotiationMessage *response,
        negotiation = ENCRYPTION_NEGOTIATION_MESSAGE__INIT;
    Envelope *env;

    /* TODO: use correct nonce */
    randombytes_buf(nonce, sizeof(nonce));
    negotiation.nonce.data = nonce;
    negotiation.nonce.len = sizeof(nonce);

    if (pack_signed_protobuf(&env, (ProtobufCMessage *) &negotiation,
                local_keys, remote_keys) < 0) {
        puts("Could not pack negotiation");
        return -1;
    }
    if (sd_channel_write_protobuf(channel, (ProtobufCMessage *) env) < 0) {
        puts("Could not send negotiation");
        return -1;
    }
    envelope__free_unpacked(env, NULL);

    if (sd_channel_receive_protobuf(channel, &envelope__descriptor,
            (ProtobufCMessage **) &env) < 0) {
        puts("Failed receiving negotiation response");
        return -1;
    }
    if (unpack_signed_protobuf(&encryption_negotiation_message__descriptor,
                (ProtobufCMessage **) &response, env, local_keys) < 0) {
        puts("Failed unpacking protobuf");
        return -1;
    }
    envelope__free_unpacked(env, NULL);

    if (sd_channel_set_crypto_asymmetric(channel, local_keys, remote_keys,
                nonce, response->nonce.data) < 0) {
        puts("Failed enabling encryption");
        return -1;
    }

    encryption_negotiation_message__free_unpacked(response, NULL);

    return 0;
}

int await_encryption(struct sd_channel *channel, const struct sd_key_pair *local_keys)
{
    uint8_t nonce[crypto_box_NONCEBYTES];
    struct sd_key_public remote_keys;
    EncryptionNegotiationMessage *negotiation,
        response = ENCRYPTION_NEGOTIATION_MESSAGE__INIT;
    Envelope *env;

    if (sd_channel_receive_protobuf(channel,
            (ProtobufCMessageDescriptor *) &envelope__descriptor,
            (ProtobufCMessage **) &env) < 0) {
        puts("Failed receiving protobuf");
        return -1;
    }

    if (unpack_signed_protobuf(&encryption_negotiation_message__descriptor,
                (ProtobufCMessage **) &negotiation, env, local_keys) < 0) {
        puts("Failed unpacking protobuf");
        return -1;
    }
    if (sd_key_public_from_bin(&remote_keys, env->pk.data, env->pk.len) < 0 ) {
        puts("Could not extract remote keys");
        return -1;
    }
    envelope__free_unpacked(env, NULL);

    /* TODO: use correct nonce */
    randombytes_buf(nonce, sizeof(nonce));
    response.nonce.data = nonce;
    response.nonce.len = sizeof(nonce);

    if (pack_signed_protobuf(&env, (ProtobufCMessage *) &response,
                local_keys, &remote_keys) < 0) {
        puts("Could not pack query");
        return -1;
    }
    if (sd_channel_write_protobuf(channel, (ProtobufCMessage *) env) < 0) {
        puts("Could not send query");
        return -1;
    }
    envelope__free_unpacked(env, NULL);

    sd_channel_set_crypto_asymmetric(channel, local_keys, &remote_keys, nonce, negotiation->nonce.data);
    encryption_negotiation_message__free_unpacked(negotiation, NULL);

    return 0;
}
