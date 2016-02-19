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
#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sodium/crypto_auth.h>
#include <sodium/utils.h>
#include <sodium/randombytes.h>

#include "lib/log.h"

#include "channel.h"

#include "proto/envelope.pb-c.h"

int getsock(struct sockaddr_storage *addr, const char *host,
        const char *port, enum sd_channel_type type)
{
    struct addrinfo hints, *servinfo, *hint;
    int ret, fd;

    memset(&hints, 0, sizeof(hints));
    switch (type) {
        case SD_CHANNEL_TYPE_TCP:
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            break;
        case SD_CHANNEL_TYPE_UDP:
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;
            break;
        default:
            sd_log(LOG_LEVEL_ERROR, "Unknown channel type");
            return -1;
    }

    if (host == NULL)
        hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(host, port, &hints, &servinfo);
    if (ret != 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not get addrinfo for address %s:%s",
                host, port);
        return -1;
    }

    for (hint = servinfo; hint != NULL; hint = hint->ai_next) {
        fd = socket(hint->ai_family, hint->ai_socktype, hint->ai_protocol);
        if (fd < 0)
            continue;

        break;
    }

    if (hint == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Unable to resolve address");
        return -1;
    }

    if (hint->ai_addrlen > sizeof(struct sockaddr_storage)) {
        sd_log(LOG_LEVEL_ERROR, "Hint's addrlen is greater than sockaddr_storage length");
        return -1;
    }

    memcpy(addr, hint->ai_addr, hint->ai_addrlen);
    freeaddrinfo(servinfo);

    return fd;
}

int sd_channel_init_from_host(struct sd_channel *c, const char *host,
        const char *port, enum sd_channel_type type)
{
    int fd;
    struct sockaddr_storage addr;

    fd = getsock(&addr, host, port, type);
    if (fd < 0) {
        return -1;
    }

    return sd_channel_init_from_fd(c, fd, addr, type);
}

int sd_channel_init_from_fd(struct sd_channel *c,
        int fd, struct sockaddr_storage addr, enum sd_channel_type type)
{
    memset(c, 0, sizeof(struct sd_channel));
    c->nonce_offset = 2;

    c->fd = fd;
    c->type = type;
    c->crypto = SD_CHANNEL_CRTYPTO_NONE;
    c->addr = addr;

    return 0;
}

int sd_channel_set_crypto_none(struct sd_channel *c)
{
    memset(&c->local_keys, 0, sizeof(c->local_keys));
    memset(&c->remote_keys, 0, sizeof(c->remote_keys));

    c->crypto = SD_CHANNEL_CRTYPTO_NONE;

    return 0;
}

int sd_channel_set_crypto_encrypt(struct sd_channel *c,
        const struct sd_keys *local_keys,
        const struct sd_keys_public *remote_keys,
        uint8_t *local_nonce, uint8_t *remote_nonce)
{
    memcpy(&c->local_keys, local_keys, sizeof(c->local_keys));
    memcpy(&c->remote_keys, remote_keys, sizeof(c->remote_keys));

    memcpy(c->local_nonce, local_nonce, sizeof(c->local_nonce));
    memcpy(c->remote_nonce, remote_nonce, sizeof(c->remote_nonce));

    c->crypto = SD_CHANNEL_CRTYPTO_ENCRYPT;

    return 0;
}

int sd_channel_close(struct sd_channel *c)
{
    if (c->fd < 0) {
        sd_log(LOG_LEVEL_WARNING, "Closing channel with invalid fd");
        return -1;
    }

    close(c->fd);
    c->fd = -1;

    return 0;
}

int sd_channel_connect(struct sd_channel *c)
{
    assert(c->fd >= 0);

    if (connect(c->fd, (struct sockaddr*) &c->addr, sizeof(c->addr)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not connect: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int sd_channel_write_data(struct sd_channel *c, uint8_t *data, uint32_t datalen)
{
    uint8_t msg[4096 + crypto_box_MACBYTES];
    ssize_t ret;
    int i;

    switch (c->crypto) {
        case SD_CHANNEL_CRTYPTO_NONE:
            if (datalen > sizeof(msg)) {
                sd_log(LOG_LEVEL_ERROR,
                        "Data buffer bigger then internal buffer");
                return -1;
            }

            memcpy(msg, data, datalen);
            break;
        case SD_CHANNEL_CRTYPTO_ENCRYPT:
            if (datalen > sizeof(msg) - crypto_box_MACBYTES) {
                sd_log(LOG_LEVEL_ERROR,
                        "Data buffer bigger then internal buffer");
                return -1;
            }

            if (crypto_box_easy(msg, data, datalen,
                    c->local_nonce, c->remote_keys.box, c->local_keys.sk.box) < 0) {
                sd_log(LOG_LEVEL_ERROR, "Unable to encrypt msg");
                return -1;
            }
            datalen = datalen + crypto_box_MACBYTES;

            break;
        default:
            sd_log(LOG_LEVEL_ERROR, "Unknown crypto type");
            return -1;
    }

    switch (c->type) {
        case SD_CHANNEL_TYPE_TCP:
            /* prefix with data length */
            /* TODO: encrypt length */
            ret = send(c->fd, (uint8_t *) &datalen, sizeof(uint32_t) / sizeof(uint8_t), 0);
            ret = send(c->fd, msg, datalen, 0);
            break;
        case SD_CHANNEL_TYPE_UDP:
            /* prefix with data length */
            /* TODO: encrypt length */
            ret = sendto(c->fd, (uint8_t *) &datalen, sizeof(uint32_t) / sizeof(uint8_t), 0,
                    (struct sockaddr *) &c->addr, sizeof(c->addr));
            ret = sendto(c->fd, msg, datalen, 0,
                    (struct sockaddr *) &c->addr, sizeof(c->addr));
            break;
        default:
            sd_log(LOG_LEVEL_ERROR, "Unknown channel type");
            return -1;
    }

    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not send data: %s",
                strerror(errno));
        return -1;
    } else if ((size_t) ret != datalen) {
        sd_log(LOG_LEVEL_ERROR, "Buffer not wholly transmittedd");
        return -1;
    }

    for (i = 0; i < c->nonce_offset; i++)
        sodium_increment(c->local_nonce, crypto_box_NONCEBYTES);

    return 0;
}

int sd_channel_write_protobuf(struct sd_channel *c, ProtobufCMessage *msg)
{
    size_t size;
    uint8_t buf[4096];

    size = protobuf_c_message_get_packed_size(msg);
    if (size > sizeof(buf)) {
        sd_log(LOG_LEVEL_ERROR, "Protobuf message exceeds buffer length");
        return -1;
    }

    protobuf_c_message_pack(msg, buf);

    return sd_channel_write_data(c, buf, size);
}

ssize_t sd_channel_receive_data(struct sd_channel *c, uint8_t *out, size_t maxlen)
{
    uint8_t buf[4096];
    uint32_t len;
    ssize_t ret;
    int i;

    ret = recv(c->fd, (uint8_t *) &len, sizeof(uint32_t) / sizeof(uint8_t), 0);
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not receive data length: %s",
                strerror(errno));
        return -1;
    }

    if (len > sizeof(buf)) {
        sd_log(LOG_LEVEL_ERROR, "Data length exceeds buffer");
        return -1;
    }

    ret = recv(c->fd, buf, len, 0);
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not receive data: %s",
                strerror(errno));
        return -1;
    } else if (len != ret) {
        sd_log(LOG_LEVEL_ERROR, "Unexpected size received");
        return -1;
    }

    switch (c->crypto) {
        case SD_CHANNEL_CRTYPTO_NONE:
            if ((size_t) len > maxlen) {
                sd_log(LOG_LEVEL_ERROR,
                        "Data buffer bigger then internal buffer");
                return -1;
            }

            memcpy(out, buf, len);
            break;
        case SD_CHANNEL_CRTYPTO_ENCRYPT:
            if ((size_t) len - crypto_box_MACBYTES > maxlen) {
                sd_log(LOG_LEVEL_ERROR,
                        "Data buffer bigger then internal buffer");
                return -1;
            }

            if (crypto_box_open_easy(out, buf, len, c->remote_nonce,
                        c->remote_keys.box, c->local_keys.sk.box) != 0) {
                sd_log(LOG_LEVEL_ERROR, "Unable to decrypt message");
                return -1;
            }
            len = len - crypto_box_MACBYTES;

            break;
        default:
            sd_log(LOG_LEVEL_ERROR, "Unknown crypto type");
            return -1;
    }

    for (i = 0; i < c->nonce_offset; i++)
        sodium_increment(c->remote_nonce, crypto_box_NONCEBYTES);

    return len;
}

int sd_channel_receive_protobuf(struct sd_channel *c, const ProtobufCMessageDescriptor *descr, ProtobufCMessage **msg)
{
    ProtobufCMessage *result;
    uint8_t buf[4096];
    ssize_t len;

    len = sd_channel_receive_data(c, buf, sizeof(buf));
    if (len < 0) {
        return -1;
    }

    result = protobuf_c_message_unpack(descr, NULL, len, buf);
    if (result == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Protobuf message could not be unpacked");
        return -1;
    }

    *msg = result;

    return 0;
}
