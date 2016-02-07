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

#include <sodium/crypto_box.h>
#include <sodium/crypto_sign.h>

#include "lib/log.h"

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

int pack_signed_protobuf(Envelope **out, const ProtobufCMessage *msg, uint8_t *pk, uint8_t *sk)
{
    Envelope *env;
    uint8_t mac[crypto_sign_BYTES];
    uint8_t *buf;
    int len;

    *out = NULL;

    len = protobuf_c_message_get_packed_size(msg);
    buf = malloc(len);
    protobuf_c_message_pack(msg, buf);

    if (crypto_sign_detached(mac, NULL, buf, len, sk) != 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to sign protobuf");
        return -1;
    }

    env = malloc(sizeof(Envelope));
    envelope__init(env);

    env->data.data = buf;
    env->data.len = len;

    env->pk.data = malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
    memcpy(env->pk.data, pk, crypto_sign_ed25519_PUBLICKEYBYTES);
    env->pk.len = crypto_sign_ed25519_PUBLICKEYBYTES;

    env->mac.data = malloc(crypto_sign_BYTES);
    memcpy(env->mac.data, mac, crypto_sign_BYTES);
    env->mac.len = crypto_sign_BYTES;

    if (env->encrypted) {
        sd_log(LOG_LEVEL_ERROR, "Encrypted signed messages not supported");
        return -1;
    }
    env->encrypted = 0;

    *out = env;

    return 0;
}

int unpack_signed_protobuf(const ProtobufCMessageDescriptor *descr,
        ProtobufCMessage **out, const Envelope *env)
{
    ProtobufCMessage *msg;

    *out = NULL;

    if (crypto_sign_verify_detached(env->mac.data,
                env->data.data, env->data.len, env->pk.data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to verify signed protobuf");
        return -1;
    }

    msg = protobuf_c_message_unpack(descr, NULL,
            env->data.len, env->data.data);
    if (msg == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Unable to unpack signed protobuf");
        return -1;
    }

    *out = msg;

    return 0;
}
