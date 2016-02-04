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

#include "common.h"
#include "channel.h"
#include "log.h"

#include "proto/envelope.pb-c.h"

static int getsock(struct sockaddr_storage *addr, const char *host,
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
    }

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

void sd_channel_init(struct sd_channel *c)
{
    memset(c, 0, sizeof(struct sd_channel));
    c->local_fd = -1;
    c->remote_fd = -1;
}

int sd_channel_set_local_address(struct sd_channel *c, const char *host,
        const char *port, enum sd_channel_type type)
{
    int fd, opt;

    fd = getsock(&c->laddr, host, port, type);
    if (fd < 0) {
        return -1;
    }

    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not set socket option: %s", strerror(errno));
        return -1;
    }

    c->local_fd = fd;

    return 0;
}

int sd_channel_set_remote_address(struct sd_channel *c, const char *host,
        const char *port, enum sd_channel_type type)
{
    int fd;

    fd = getsock(&c->raddr, host, port, type);
    if (fd < 0) {
        return -1;
    }

    c->remote_fd = fd;

    return 0;
}

int sd_channel_set_crypto_none(struct sd_channel *c)
{
    memset(c->public_key, 0, sizeof(c->public_key));
    memset(c->secret_key, 0, sizeof(c->secret_key));
    memset(c->remote_key, 0, sizeof(c->remote_key));

    c->crypto = SD_CHANNEL_CRTYPTO_NONE;

    return 0;
}

int sd_channel_set_crypto_sign(struct sd_channel *c, uint8_t *pk, uint8_t *sk)
{
    memset(c->remote_key, 0, sizeof(c->remote_key));

    memcpy(c->public_key, pk, sizeof(c->public_key));
    memcpy(c->secret_key, sk, sizeof(c->secret_key));

    c->crypto = SD_CHANNEL_CRTYPTO_SIGN;

    return 0;
}

int sd_channel_set_crypto_encrypt(struct sd_channel *c, uint8_t *sk, uint8_t *rk)
{
    memset(c->public_key, 0, sizeof(c->public_key));

    memcpy(c->secret_key, sk, sizeof(c->secret_key));
    memcpy(c->remote_key, rk, sizeof(c->remote_key));

    c->crypto = SD_CHANNEL_CRTYPTO_ENCRYPT;

    return 0;
}

int sd_channel_close(struct sd_channel *c)
{
    if (c->local_fd < 0 && c->remote_fd < 0) {
        sd_log(LOG_LEVEL_WARNING, "Closing channel with invalid fd");
        return -1;
    }

    close(c->local_fd);
    c->local_fd = -1;
    close(c->remote_fd);
    c->remote_fd = -1;

    return 0;
}

int sd_channel_connect(struct sd_channel *c)
{
    assert(c->remote_fd >= 0);

    if (connect(c->remote_fd, (struct sockaddr*) &c->raddr, sizeof(c->raddr)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not connect: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int sd_channel_listen(struct sd_channel *c)
{
    int fd;

    assert(c->local_fd >= 0);

    if (bind(c->local_fd, (struct sockaddr*) &c->laddr, sizeof(c->laddr)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not bind socket: %s", strerror(errno));
        return -1;
    }

    fd = listen(c->local_fd, 16);
    if (fd < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not listen: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int sd_channel_accept(struct sd_channel *c)
{
    int fd;
    unsigned int addrsize;
    struct sockaddr_storage addr;

    assert(c->local_fd >= 0);

    addrsize = sizeof(addr);

    fd = accept(c->local_fd, (struct sockaddr*) &addr, &addrsize);
    if (fd < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not accept connection: %s",
                strerror(errno));
        return -1;
    }

    c->remote_fd = fd;
    c->raddr = addr;

    return 0;
}

int sd_channel_write_data(struct sd_channel *c, uint8_t *buf, size_t len)
{
    ssize_t ret;

    ret = send(c->remote_fd, buf, len, 0);
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not send data: %s",
                strerror(errno));
        return -1;
    } else if ((size_t) ret != len) {
        sd_log(LOG_LEVEL_ERROR, "Buffer not wholly transimmted");
        return -1;
    }

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

static int unpack_signed_data(struct sd_channel *c, const uint8_t *buf, size_t len,
        uint8_t *out, size_t outlen)
{
    Envelope *envelope;
    int ret;

    envelope = envelope__unpack(NULL, len, buf);
    if (envelope == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Unable to unpack signed envelope");
        return -1;
    }

    ret = crypto_auth_verify(envelope->mac.data, envelope->data.data,
            envelope->data.len, envelope->pk.data);
    if (ret < 0) {
        ret = -1;
        goto out;
    }

    if (envelope->encrypted) {
        uint8_t plaintext[4096];

        if (crypto_box_open_easy(plaintext, buf, len, c->nonce,
                envelope->pk.data, c->secret_key) != 0) {
            sd_log(LOG_LEVEL_ERROR, "Unable to decrypt signed message");
            ret = -1;
            goto out;
        }
    }

    if (envelope->data.len <= outlen) {
        memcpy(out, envelope->data.data, envelope->data.len);
    } else {
        sd_log(LOG_LEVEL_ERROR, "Signed message bigger than passed buffer");
        ret = -1;
        goto out;
    }

out:
    envelope__free_unpacked(envelope, NULL);

    return ret;
}

ssize_t sd_channel_receive_data(struct sd_channel *c, uint8_t *out, size_t maxlen)
{
    uint8_t buf[4096];
    unsigned int addrlen;
    ssize_t len;

    addrlen = sizeof(c->raddr);

    len = recvfrom(c->local_fd, buf, sizeof(buf), 0, (struct sockaddr*) &c->raddr, &addrlen);
    if (len < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not receive data: %s",
                strerror(errno));
        return -1;
    }

    if ((size_t) len > maxlen) {
        sd_log(LOG_LEVEL_ERROR, "Buffer smaller than message");
        return -1;
    }

    switch (c->crypto) {
        case SD_CHANNEL_CRTYPTO_NONE:
            memcpy(out, buf, len);
            break;
        case SD_CHANNEL_CRTYPTO_SIGN:
            len = unpack_signed_data(c, out, maxlen, buf, sizeof(buf));
            break;
        case SD_CHANNEL_CRTYPTO_ENCRYPT:
            if (crypto_box_open_easy(out, buf, sizeof(buf), c->nonce,
                        c->remote_key, c->secret_key) != 0) {
                sd_log(LOG_LEVEL_ERROR, "Unable to decrypt message");
                return -1;
            }
            break;
    }

    return len;
}

int sd_channel_recveive_protobuf(struct sd_channel *c, ProtobufCMessageDescriptor *descr, ProtobufCMessage **msg)
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
