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

#include "lib/common.h"
#include "lib/server.h"

int main(int argc, char *argv[])
{
    const char *config, *port;
    struct sd_channel channel;
    struct sd_server server;
    struct sd_keys keys;

    if (argc != 3) {
        printf("USAGE: %s <CONFIG> <PORT>\n", argv[0]);
        return -1;
    }

    config = argv[1];
    port = argv[2];

    if (sodium_init() < 0) {
        puts("Could not init libsodium");
        return -1;
    }

    if (sd_keys_from_config_file(&keys, config) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (sd_server_init(&server, NULL, port, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Could not set up server");
        return -1;
    }

    if (sd_server_listen(&server) < 0) {
        puts("Could not start listening");
        return -1;
    }

    if (sd_server_accept(&server, &channel) < 0) {
        puts("Could not accept connection");
        return -1;
    }

    sd_server_close(&server);

    return 0;
}
