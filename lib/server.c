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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "capone/log.h"
#include "capone/server.h"

static int get_server_socket(struct sockaddr_storage *addr, const char *host,
        const char *port, enum cpn_channel_type type)
{
    struct addrinfo hints, *servinfo, *hint;
    int ret, fd, opt;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    switch (type) {
        case CPN_CHANNEL_TYPE_TCP:
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;
            break;
        case CPN_CHANNEL_TYPE_UDP:
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;
            break;
        default:
            cpn_log(LOG_LEVEL_ERROR, "Unknown channel type");
            return -1;
    }
    hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(host, port, &hints, &servinfo);
    if (ret != 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not get addrinfo for address %s:%s",
                host, port);
        return -1;
    }

    for (hint = servinfo; hint != NULL; hint = hint->ai_next) {
        fd = socket(hint->ai_family, hint->ai_socktype, hint->ai_protocol);
        if (fd < 0)
            continue;

        opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0 ||
                bind(fd, hint->ai_addr, hint->ai_addrlen) < 0)
        {
            cpn_log(LOG_LEVEL_DEBUG, "Unsuitable socket: %s", strerror(errno));
            close(fd);
            continue;
        }

        break;
    }

    if (hint == NULL) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to resolve address");
        freeaddrinfo(servinfo);
        return -1;
    }

    if ((size_t) hint->ai_addrlen > sizeof(struct sockaddr_storage)) {
        cpn_log(LOG_LEVEL_ERROR, "Hint's addrlen is greater than sockaddr_storage length");
        freeaddrinfo(servinfo);
        close(fd);
        return -1;
    }

    memcpy(addr, hint->ai_addr, hint->ai_addrlen);
    freeaddrinfo(servinfo);

    return fd;
}

int cpn_server_init(struct cpn_server *server,
        const char *host, const char *port, enum cpn_channel_type type)
{
    int fd;
    struct sockaddr_storage addr;

    fd = get_server_socket(&addr, host, port, type);
    if (fd < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to get socket: %s", strerror(errno));
        return -1;
    }

    server->fd = fd;
    server->type = type;
    server->addr = addr;

    return 0;
}

int cpn_server_close(struct cpn_server *server)
{
    if (server->fd < 0) {
        cpn_log(LOG_LEVEL_WARNING, "Closing channel with invalid fd");
        return -1;
    }

    close(server->fd);
    server->fd = -1;

    return 0;
}

int cpn_server_enable_broadcast(struct cpn_server *server)
{
    int val = 1;

    if (setsockopt(server->fd, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to set option on socket: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int cpn_server_listen(struct cpn_server *s)
{
    int fd;

    assert(s->fd >= 0);

    fd = listen(s->fd, 16);
    if (fd < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not listen: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int cpn_server_accept(struct cpn_server *s, struct cpn_channel *out)
{
    int fd;
    socklen_t addrsize;
    struct sockaddr_storage addr;

    assert(s->fd >= 0);

    addrsize = sizeof(addr);

    switch (s->type) {
        case CPN_CHANNEL_TYPE_TCP:
            while (1) {
                fd = accept(s->fd, (struct sockaddr*) &addr, &addrsize);

                if (fd < 0) {
                    if (errno == EAGAIN || errno == EINTR)
                        continue;
                    cpn_log(LOG_LEVEL_ERROR, "Could not accept connection: %s",
                            strerror(errno));
                    return -1;
                }

                break;
            }
            break;
        case CPN_CHANNEL_TYPE_UDP:
            if (recvfrom(s->fd, NULL, 0, MSG_PEEK,
                        (struct sockaddr *)&addr, &addrsize) < 0) {
                cpn_log(LOG_LEVEL_ERROR, "Could not peek message");
                return -1;
            }
            fd = s->fd;
            break;
        default:
            cpn_log(LOG_LEVEL_ERROR, "Unknown channel type");
            return -1;
    }

    return cpn_channel_init_from_fd(out, fd, (struct sockaddr *) &addr, addrsize, s->type);
}

int cpn_server_get_address(struct cpn_server *s,
        char *host, size_t hostlen, char *port, size_t portlen)
{
    struct sockaddr_storage addr;
    socklen_t addrlen;

    addrlen = sizeof(addr);
    if (getsockname(s->fd, (struct sockaddr *)&addr, &addrlen) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not get socket name: %s", strerror(errno));
        return -1;
    }

    if (getnameinfo((struct sockaddr *) &addr,
                addrlen, host, hostlen, port, portlen,
                NI_NUMERICHOST | NI_NUMERICSERV) != 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Could not resolve name info: %s", strerror(errno));
        return -1;
    }

    return 0;
}
