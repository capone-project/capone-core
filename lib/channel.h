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

#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <protobuf-c/protobuf-c.h>

#include <sodium/crypto_box.h>

typedef void *(unpack_fn)(ProtobufCAllocator *allocator, size_t len, const uint8_t *data);
typedef size_t (pack_fn)(const void *protobuf, uint8_t *out);
typedef size_t (size_fn)(const void *protobuf);

enum sd_channel_type {
    SD_CHANNEL_TYPE_UDP,
    SD_CHANNEL_TYPE_TCP,
};

enum sd_channel_crypto {
    SD_CHANNEL_CRTYPTO_NONE,
    SD_CHANNEL_CRTYPTO_ENCRYPT,
};

struct sd_channel {
    int local_fd;
    int remote_fd;

    enum sd_channel_type type;
    enum sd_channel_crypto crypto;

    struct sockaddr_storage laddr;
    struct sockaddr_storage raddr;

    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t secret_key[crypto_box_SECRETKEYBYTES];
    uint8_t remote_key[crypto_box_PUBLICKEYBYTES];

    uint8_t remote_nonce[crypto_box_NONCEBYTES];
    uint8_t local_nonce[crypto_box_NONCEBYTES];
    uint8_t nonce_offset;
};

void sd_channel_init(struct sd_channel *c);
int sd_channel_close(struct sd_channel *c);

int sd_channel_set_local_address(struct sd_channel *c,
        const char *host, const char *port, enum sd_channel_type type);
int sd_channel_set_remote_address(struct sd_channel *c,
        const char *host, const char *port, enum sd_channel_type type);

int sd_channel_set_crypto_none(struct sd_channel *c);
int sd_channel_set_crypto_encrypt(struct sd_channel *c,
        uint8_t *pk, uint8_t *sk, uint8_t *rk,
        uint8_t *local_nonce, uint8_t *remote_nonce);

int sd_channel_connect(struct sd_channel *c);
int sd_channel_listen(struct sd_channel *c);
int sd_channel_accept(struct sd_channel *c);

int sd_channel_write_data(struct sd_channel *c, uint8_t *buf, size_t len);
ssize_t sd_channel_receive_data(struct sd_channel *c, uint8_t *buf, size_t maxlen);
int sd_channel_write_protobuf(struct sd_channel *c, ProtobufCMessage *msg);
int sd_channel_receive_protobuf(struct sd_channel *c, ProtobufCMessageDescriptor *descr, ProtobufCMessage **msg);
