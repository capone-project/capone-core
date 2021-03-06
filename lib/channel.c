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
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "capone/log.h"
#include "capone/common.h"
#include "capone/channel.h"

#define DEFAULT_BLOCKLEN 512
#define MAX_BLOCKLEN 4096

extern int get_socket(struct sockaddr_storage *addr, socklen_t *addrlen,
        const char *host, uint32_t port,
        enum cpn_channel_type type,
        bool serverside);

int cpn_channel_init_from_host(struct cpn_channel *c, const char *host,
        uint32_t port, enum cpn_channel_type type)
{
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;

    fd = get_socket(&addr, &addrlen, host, port, type, false);
    if (fd < 0) {
        return -1;
    }

    return cpn_channel_init_from_fd(c, fd, (struct sockaddr *) &addr, addrlen, type);
}

int cpn_channel_init_from_fd(struct cpn_channel *c,
        int fd, const struct sockaddr *addr, size_t addrlen,
        enum cpn_channel_type type)
{
    memset(c, 0, sizeof(struct cpn_channel));

    assert(addrlen <= sizeof(c->addr));

    c->blocklen = DEFAULT_BLOCKLEN;
    c->fd = fd;
    c->type = type;
    c->crypto = CPN_CHANNEL_CRYPTO_NONE;
    memcpy(&c->addr, addr, addrlen);
    c->addrlen = addrlen;

    return 0;
}

int cpn_channel_set_blocklen(struct cpn_channel *c, size_t len)
{
    if (len < sizeof(uint32_t) + CPN_CRYPTO_SYMMETRIC_MACBYTES + 1) {
        return -1;
    } else if (len > MAX_BLOCKLEN) {
        return -1;
    }

    c->blocklen = len;

    return 0;
}

int cpn_channel_enable_encryption(struct cpn_channel *c,
        const struct cpn_symmetric_key *key, enum cpn_channel_nonce nonce)
{
    memcpy(&c->key, key, sizeof(c->key));

    memset(&c->local_nonce, 0, sizeof(c->local_nonce));
    memset(&c->remote_nonce, 0, sizeof(c->remote_nonce));

    switch (nonce) {
        case CPN_CHANNEL_NONCE_CLIENT:
            cpn_symmetric_key_nonce_increment(&c->remote_nonce, 1);
            break;
        case CPN_CHANNEL_NONCE_SERVER:
            cpn_symmetric_key_nonce_increment(&c->local_nonce, 1);
            break;
    }

    c->crypto = CPN_CHANNEL_CRYPTO_SYMMETRIC;

    return 0;
}

int cpn_channel_close(struct cpn_channel *c)
{
    if (c->fd < 0) {
        cpn_log(LOG_LEVEL_WARNING, "Closing channel with invalid fd");
        return -1;
    }

    close(c->fd);
    c->fd = -1;

    return 0;
}

int cpn_channel_connect(struct cpn_channel *c)
{
    assert(c->fd >= 0);

    if (connect(c->fd, (struct sockaddr*) &c->addr, c->addrlen) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not connect: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static int write_data(struct cpn_channel *c, uint8_t *data, uint32_t datalen)
{
    ssize_t ret;
    uint32_t written = 0;

    while (written != datalen) {
        switch (c->type) {
            case CPN_CHANNEL_TYPE_TCP:
                ret = send(c->fd, data + written, datalen - written, 0);
                break;
            case CPN_CHANNEL_TYPE_UDP:
                ret = sendto(c->fd, data + written, datalen - written, 0,
                        (struct sockaddr *) &c->addr, c->addrlen);
                break;
            default:
                cpn_log(LOG_LEVEL_ERROR, "Unknown channel type");
                return -1;
        }

        if (ret < 0) {
            if (errno == EINTR)
                continue;
            cpn_log(LOG_LEVEL_ERROR, "Could not send data: %s",
                    strerror(errno));
            return -1;
        } else if (ret == 0) {
            cpn_log(LOG_LEVEL_VERBOSE, "Channel closed while writing");
            return 0;
        }

        written += ret;
    }

    return written;
}

int cpn_channel_write_data(struct cpn_channel *c, uint8_t *data, uint32_t datalen)
{
    uint8_t block[MAX_BLOCKLEN];
    size_t written = 0, offset;
    uint32_t networklen;

    networklen = htonl(datalen);
    memcpy(block, &networklen, sizeof(networklen));
    offset = 4;

    while (offset || written != datalen) {
        uint32_t len;
        ssize_t ret;

        if (c->crypto == CPN_CHANNEL_CRYPTO_SYMMETRIC) {
            len = MIN(datalen - written, c->blocklen - offset - CPN_CRYPTO_SYMMETRIC_MACBYTES);
        } else {
            len = MIN(datalen - written, c->blocklen - offset);
        }

        memset(block + offset, 0, c->blocklen - offset);
        memcpy(block + offset, data + written, len);

        if (c->crypto == CPN_CHANNEL_CRYPTO_SYMMETRIC) {
            if (cpn_symmetric_key_encrypt(block, &c->key, &c->local_nonce,
                        block, c->blocklen - CPN_CRYPTO_SYMMETRIC_MACBYTES) < 0)
            {
                cpn_log(LOG_LEVEL_ERROR, "Unable to encrypt message");
                return -1;
            }
            cpn_symmetric_key_nonce_increment(&c->local_nonce, 2);
        }

        ret = write_data(c, block, c->blocklen);
        if (ret == 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to write data: channel closed");
            return 0;
        } else if (ret < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to write data");
            return -1;
        }
        written += len;

        offset = 0;
    }

    return 0;
}

int cpn_channel_write_protobuf(struct cpn_channel *c, const ProtobufCMessage *msg)
{
    const char *pkgname, *descrname;
    size_t size;
    uint8_t buf[4096];

    if (!protobuf_c_message_check(msg)) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid protobuf message");
        return -1;
    }

    size = protobuf_c_message_get_packed_size(msg);
    if (size > sizeof(buf)) {
        cpn_log(LOG_LEVEL_ERROR, "Protobuf message exceeds buffer length");
        return -1;
    }

    pkgname = msg->descriptor->package_name;
    descrname = msg->descriptor->name;

    cpn_log(LOG_LEVEL_TRACE, "Writing protobuf %s:%s of length %"PRIuMAX,
            pkgname ? pkgname : "", descrname ? descrname : "", size);

    protobuf_c_message_pack(msg, buf);

    return cpn_channel_write_data(c, buf, size);
}

static int receive_data(struct cpn_channel *c, uint8_t *out, size_t len)
{
    ssize_t ret;
    size_t received = 0;

    while (received != len) {
        switch (c->type) {
            case CPN_CHANNEL_TYPE_TCP:
                ret = recv(c->fd, out + received, len - received, 0);
                break;
            case CPN_CHANNEL_TYPE_UDP:
                ret = recvfrom(c->fd, out + received, len - received, 0,
                        (struct sockaddr *) &c->addr, &c->addrlen);
                break;
        }

        if (ret == 0) {
            cpn_log(LOG_LEVEL_VERBOSE, "Channel closed while receiving",
                    strerror(errno));
            return 0;
        } else if (ret < 0) {
            if (errno == EINTR)
                continue;
            cpn_log(LOG_LEVEL_ERROR, "Could not receive data: %s",
                    strerror(errno));
            return -1;
        }

        received += ret;
    }

    return received;
}

ssize_t cpn_channel_receive_data(struct cpn_channel *c, uint8_t *out, size_t maxlen)
{
    uint8_t block[MAX_BLOCKLEN];
    uint32_t pkglen, received = 0, offset = sizeof(uint32_t);

    while (offset || received < pkglen) {
        uint32_t networklen, blocklen;
        ssize_t ret;

        ret = receive_data(c, block, c->blocklen);
        if (ret == 0) {
            cpn_log(LOG_LEVEL_VERBOSE, "Unable to receive data: channel closed");
            return 0;
        } else if (ret < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to receive data");
            return -1;
        }

        if (c->crypto == CPN_CHANNEL_CRYPTO_SYMMETRIC) {
            if (cpn_symmetric_key_decrypt(block, &c->key, &c->remote_nonce,
                        block, c->blocklen) < 0)
            {
                cpn_log(LOG_LEVEL_ERROR, "Unable to decrypt received block");
                return -1;
            }
            cpn_symmetric_key_nonce_increment(&c->remote_nonce, 2);
        }

        if (offset) {
            memcpy(&networklen, block, sizeof(networklen));
            pkglen = ntohl(networklen);
            if (pkglen > maxlen) {
                cpn_log(LOG_LEVEL_ERROR, "Received package length exceeds maxlen");
                return -1;
            }
        }

        if (c->crypto == CPN_CHANNEL_CRYPTO_SYMMETRIC) {
            blocklen = MIN(pkglen - received, c->blocklen - offset - CPN_CRYPTO_SYMMETRIC_MACBYTES);
        } else {
            blocklen = MIN(pkglen - received, c->blocklen - offset);
        }

        memcpy(out + received, block + offset, blocklen);

        received += blocklen;
        offset = 0;
    }

    return received;
}

int cpn_channel_receive_protobuf(struct cpn_channel *c, const ProtobufCMessageDescriptor *descr, ProtobufCMessage **msg)
{
    ProtobufCMessage *result = NULL;
    uint8_t buf[4096];
    ssize_t len;
    int ret = -1;

    if ((len = cpn_channel_receive_data(c, buf, sizeof(buf))) < 0)
        goto out;

    cpn_log(LOG_LEVEL_TRACE, "Receiving protobuf %s:%s of length %"PRIuMAX,
            descr->package_name, descr->name, len);

    if ((result = protobuf_c_message_unpack(descr, NULL, len, buf)) == NULL) {
        cpn_log(LOG_LEVEL_ERROR, "Protobuf message could not be unpacked");
        goto out;
    }

    ret = 0;

out:
    *msg = result;

    return ret;
}

int cpn_channel_relay(struct cpn_channel *channel, int nfds, ...)
{
    fd_set fds;
    uint8_t buf[2048];
    int closed = 0, written, received, maxfd, infd, fd, i, ret;
    va_list ap;

    if (nfds <= 0) {
        cpn_log(LOG_LEVEL_ERROR, "Relay called with nfds == 0");
        return -1;
    }

    FD_ZERO(&fds);
    FD_SET(channel->fd, &fds);
    maxfd = channel->fd;

    va_start(ap, nfds);
    for (i = 0; i < nfds; i++) {
        fd = va_arg(ap, int);
        FD_SET(fd, &fds);
        maxfd = MAX(maxfd, fd);

        if (i == 0)
            infd = fd;
    }
    va_end(ap);

    while (1) {
        fd_set tfds;

        memcpy(&tfds, &fds, sizeof(fd_set));

        if (select(maxfd + 1, &tfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR)
                continue;
            cpn_log(LOG_LEVEL_ERROR, "Error selecting fds");
            return -1;
        }

        if (FD_ISSET(channel->fd, &tfds)) {
            received = cpn_channel_receive_data(channel, buf, sizeof(buf));
            if (received == 0) {
                cpn_log(LOG_LEVEL_TRACE, "Channel closed, stopping relay");
                return -1;
            } else if (received < 0) {
                cpn_log(LOG_LEVEL_ERROR, "Error relaying data from channel: %s", strerror(errno));
                return -1;
            }

            written = 0;
            while (written != received) {
                ret = write(infd, buf + written, received - written);
                if (ret <= 0) {
                    cpn_log(LOG_LEVEL_ERROR, "Error relaying data to fd: %s", strerror(errno));
                    return -1;
                }
                written += ret;
            }
        }

        va_start(ap, nfds);
        for (i = 0; i < nfds; i++) {
            fd = va_arg(ap, int);

            if (FD_ISSET(fd, &tfds)) {
                received = read(fd, buf, sizeof(buf));
                if (received == 0) {
                    FD_CLR(fd, &fds);
                    closed++;
                    cpn_log(LOG_LEVEL_TRACE, "Relay file descriptor %d/%d closed", closed, nfds);
                    continue;
                } else if (received < 0) {
                    if (errno == EINTR)
                        continue;
                    cpn_log(LOG_LEVEL_ERROR, "Error relaying data from fd");
                    return -1;
                }

                if (cpn_channel_write_data(channel, buf, received) < 0) {
                    cpn_log(LOG_LEVEL_ERROR, "Error relaying data to channel");
                    return -1;
                }
            }
        }
        va_end(ap);

        if (closed == nfds) {
            cpn_log(LOG_LEVEL_TRACE, "All relay file descriptors closed");
            return 0;
        }
    }

    return 0;
}
