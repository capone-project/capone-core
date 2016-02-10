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

#include <sodium.h>

#include "proto/envelope.pb-c.h"

#define UNUSED(x) (void)(x)

typedef void (*thread_fn)(void *);

int spawn(thread_fn fn, void *payload);

int pack_signed_protobuf(Envelope **out, const ProtobufCMessage *msg, uint8_t *pk, uint8_t *sk);
int unpack_signed_protobuf(const ProtobufCMessageDescriptor *descr,
        ProtobufCMessage **out, const Envelope *env);

struct sd_keys {
    uint8_t sign_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    uint8_t sign_sk[crypto_sign_ed25519_SECRETKEYBYTES];
    uint8_t box_pk[crypto_scalarmult_curve25519_BYTES];
    uint8_t box_sk[crypto_scalarmult_curve25519_BYTES];
};

int sd_keys_from_config_file(struct sd_keys *out, const char *file);
