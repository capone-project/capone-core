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

#include "proto/envelope.pb-c.h"

#define UNUSED(x) (void)(x)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

typedef void (*thread_fn)(void *);

struct sd_channel;
struct sd_key_pair;
struct sd_key_public;

int spawn(thread_fn fn, void *payload);

int pack_signed_protobuf(Envelope **out, const ProtobufCMessage *msg,
        const struct sd_key_pair *keys, const struct sd_key_public *remote_key);
int unpack_signed_protobuf(const ProtobufCMessageDescriptor *descr,
        ProtobufCMessage **out, const Envelope *env, const struct sd_key_pair *keys);

int initiate_encryption(struct sd_channel *channel,
        const struct sd_key_pair *local_keys,
        const struct sd_key_public *remote_keys);
int await_encryption(struct sd_channel *channel,
        const struct sd_key_pair *local_keys);
