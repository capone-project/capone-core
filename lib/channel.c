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

#include "common.h"
#include "channel.h"
#include "log.h"

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

int sd_channel_write_protobuf(struct sd_channel *c, void *msg, pack_fn packfn, size_fn sizefn)
{
    size_t size;
    uint8_t buf[4096];

    size = sizefn(msg);
    if (size > sizeof(buf)) {
        sd_log(LOG_LEVEL_ERROR, "Protobuf message exceeds buffer length");
        return -1;
    }
    packfn(msg, buf);

    return sd_channel_write_data(c, buf, size);
}

ssize_t sd_channel_receive_data(struct sd_channel *c, void *buf, size_t maxlen)
{
    unsigned int addrlen;
    ssize_t len;

    addrlen = sizeof(c->raddr);

    len = recvfrom(c->local_fd, buf, maxlen, 0, (struct sockaddr*) &c->raddr, &addrlen);
    if (len < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not receive data: %s",
                strerror(errno));
        return -1;
    }

    return len;
}

int sd_channel_recveive_protobuf(struct sd_channel *c, void **msg, size_t maxlen, unpack_fn unpackfn)
{
    uint8_t buf[4096];
    ssize_t len;

    len = sd_channel_receive_data(c, buf, sizeof(buf));
    if (len < 0) {
        return -1;
    } else if ((size_t) len > maxlen) {
        sd_log(LOG_LEVEL_ERROR, "Protobuf message exceeds buffer length");
        return -1;
    }

    (*msg) = unpackfn(NULL, len, buf);

    return 0;
}
