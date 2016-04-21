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

#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "xpra.h"

#include "lib/common.h"
#include "lib/log.h"
#include "lib/server.h"
#include "lib/service.h"

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct sd_service_parameter **out)
{
    static const struct sd_service_parameter params[] = {
        { "port", NULL },
    };

    *out = params;
    return ARRAY_SIZE(params);
}

static int invoke(struct sd_channel *channel, int argc, char **argv)
{
    char buf[1], *port;
    struct sd_channel xpra_channel;

    if (argc != 2 || strcmp(argv[0], "port")) {
        puts("Usage: xpra port <PORT>");
        return -1;
    }

    port = argv[1];

    if (sd_channel_init_from_host(&xpra_channel, "127.0.0.1", port, SD_CHANNEL_TYPE_TCP) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not initialize local xpra channel");
        return -1;
    }

    /* As xpra uses a timeout waiting for initial data when
     * connecting to the service we have to make sure that the
     * remote side has already started the connection from the
     * xpra client. As such, we wait for the first byte to appear
     * and when it does, we do the actual connection to the xpra
     * server.
     */
    if (recv(channel->fd, buf, sizeof(buf), MSG_PEEK) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not await xpra connection");
        return -1;
    }

    if (sd_channel_connect(&xpra_channel) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not connect to local xpra server");
        return -1;
    }

    if (sd_channel_relay(channel, 1, xpra_channel.fd) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not relay data from xpra connection");
        return -1;
    }

    sd_channel_close(&xpra_channel);

    return 0;
}

static int handle(struct sd_channel *channel,
        const struct sd_session *session,
        const struct cfg *cfg)
{
    struct sd_server server;
    struct sd_channel xpra_channel;
    char port[10], *args[] = {
        "xpra",
        "attach",
        NULL,
        "--no-notifications",
        NULL
    };
    int len, pid;

    UNUSED(cfg);
    UNUSED(session);

    if (sd_server_init(&server, "127.0.0.1", NULL, SD_CHANNEL_TYPE_TCP) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not initialize xpra relay socket");
        return -1;
    }

    if (sd_server_listen(&server) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not listen on xpra relay socket");
        return -1;
    }

    if (sd_server_get_address(&server, NULL, 0, port, sizeof(port)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not retrieve address of xpra relay socket");
        return -1;
    }

    len = snprintf(NULL, 0, "tcp:localhost:%5s:100", port) + 1;
    args[2] = malloc(len);
    len = snprintf(args[2], len, "tcp:localhost:%5s:100", port);

    pid = fork();
    if (pid == 0) {
        if (execvp("xpra", args) != 0) {
            sd_log(LOG_LEVEL_ERROR, "Unable to execute xpra client");
            _exit(-1);
        }

        _exit(0);
    } else if (pid > 0) {
        if (sd_server_accept(&server, &xpra_channel) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not accept xpra relay socket connection");
            return -1;
        }

        if (sd_channel_relay(channel, 1, xpra_channel.fd) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not relay xpra socket");
            return -1;
        }
    } else {
        return -1;
    }

    kill(pid, SIGKILL);
    sd_log(LOG_LEVEL_VERBOSE, "Terminated xpra");
    free(args[2]);

    return 0;
}

int sd_xpra_init_service(struct sd_service *service)
{
    service->category = "Display";
    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}
