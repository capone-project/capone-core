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

#ifndef SD_LIB_CHANNEL_H
#define SD_LIB_CHANNEL_H

#include <sys/socket.h>

#include <protobuf-c/protobuf-c.h>

#include <sodium/crypto_box.h>

#include "lib/keys.h"

typedef void *(unpack_fn)(ProtobufCAllocator *allocator, size_t len, const uint8_t *data);
typedef size_t (pack_fn)(const void *protobuf, uint8_t *out);
typedef size_t (size_fn)(const void *protobuf);

enum sd_channel_type {
    SD_CHANNEL_TYPE_UDP,
    SD_CHANNEL_TYPE_TCP,
};

enum sd_channel_crypto {
    SD_CHANNEL_CRYPTO_NONE,
    SD_CHANNEL_CRYPTO_SYMMETRIC,
};

enum sd_channel_nonce {
    SD_CHANNEL_NONCE_CLIENT,
    SD_CHANNEL_NONCE_SERVER,
};

struct sd_channel {
    int fd;
    struct sockaddr_storage addr;

    enum sd_channel_type type;
    enum sd_channel_crypto crypto;

    struct sd_symmetric_key key;
    uint8_t remote_nonce[crypto_box_NONCEBYTES];
    uint8_t local_nonce[crypto_box_NONCEBYTES];
};

int sd_channel_init_from_host(struct sd_channel *c,
        const char *host, const char *port, enum sd_channel_type type);
int sd_channel_init_from_fd(struct sd_channel *c,
        int fd, struct sockaddr_storage addr, enum sd_channel_type type);
int sd_channel_close(struct sd_channel *c);

int sd_channel_disable_encryption(struct sd_channel *c);
int sd_channel_enable_encryption(struct sd_channel *c,
        const struct sd_symmetric_key *key, enum sd_channel_nonce nonce);

int sd_channel_connect(struct sd_channel *c);

int sd_channel_write_data(struct sd_channel *c, uint8_t *buf, uint32_t len);
ssize_t sd_channel_receive_data(struct sd_channel *c, uint8_t *buf, size_t maxlen);
int sd_channel_write_protobuf(struct sd_channel *c, ProtobufCMessage *msg);
int sd_channel_receive_protobuf(struct sd_channel *c, const ProtobufCMessageDescriptor *descr, ProtobufCMessage **msg);

int sd_channel_relay(struct sd_channel *c, int nfds, ...);

#endif
