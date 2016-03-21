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

#ifndef SD_LIB_SERVER_H
#define SD_LIB_SERVER_H

#include "lib/channel.h"

struct sd_server {
    int fd;
    struct sockaddr_storage addr;
    enum sd_channel_type type;
};

int sd_server_init(struct sd_server *server,
        const char *host, const char *port, enum sd_channel_type type);
int sd_server_close(struct sd_server *server);

int sd_server_enable_broadcast(struct sd_server *server);

int sd_server_listen(struct sd_server *server);
int sd_server_accept(struct sd_server *server, struct sd_channel *out);

int sd_server_get_address(struct sd_server *s,
        char *host, size_t hostlen, char *port, size_t portlen);

#endif
