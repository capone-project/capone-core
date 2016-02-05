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

#include "lib/log.h"

#include "server.h"

extern int getsock(struct sockaddr_storage *addr, const char *host,
        const char *port, enum sd_channel_type type);

int sd_server_init(struct sd_server *server,
        const char *host, const char *port, enum sd_channel_type type)
{
    int fd, opt;
    struct sockaddr_storage addr;

    fd = getsock(&addr, host, port, type);
    if (fd < 0) {
        return -1;
    }

    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not set socket option: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not bind socket: %s", strerror(errno));
        close(fd);
        return -1;
    }

    server->fd = fd;
    server->type = type;
    server->addr = addr;

    return 0;
}

int sd_server_close(struct sd_server *server)
{
    if (server->fd < 0) {
        sd_log(LOG_LEVEL_WARNING, "Closing channel with invalid fd");
        return -1;
    }

    close(server->fd);
    server->fd = -1;

    return 0;
}

int sd_server_listen(struct sd_server *s)
{
    int fd;

    assert(s->fd >= 0);

    fd = listen(s->fd, 16);
    if (fd < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not listen: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int sd_server_accept(struct sd_server *s, struct sd_channel *out)
{
    int fd;
    unsigned int addrsize;
    struct sockaddr_storage addr;

    assert(s->fd >= 0);

    addrsize = sizeof(addr);

    switch (s->type) {
        case SD_CHANNEL_TYPE_TCP:
            fd = accept(s->fd, (struct sockaddr*) &addr, &addrsize);
            if (fd < 0) {
                sd_log(LOG_LEVEL_ERROR, "Could not accept connection: %s",
                        strerror(errno));
                return -1;
            }
            break;
        case SD_CHANNEL_TYPE_UDP:
            if (recvfrom(s->fd, NULL, 0, 0,
                        (struct sockaddr *)&addr, &addrsize) < 0) {
                sd_log(LOG_LEVEL_ERROR, "Could not peek message");
                return -1;
            }
            fd = s->fd;
            break;
    }

    return sd_channel_init_from_fd(out, fd, addr, s->type);
}
