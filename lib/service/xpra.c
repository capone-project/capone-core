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
    static const char *resolutions[] = { "1920x1080", "1024x860" };
    static const char *boolean[] = { "true", "false" };
    static const struct sd_service_parameter params[] = {
        { "resolution", ARRAY_SIZE(resolutions), resolutions },
        { "clipboard", ARRAY_SIZE(boolean), boolean },
    };

    *out = params;
    return ARRAY_SIZE(params);
}

static int invoke(struct sd_channel *channel)
{
    struct sd_channel xpra_channel;
    int pid;
    char *args[] = {
        "xpra",
        "start",
        ":100",
        "--exit-with-child",
        "--start-child=st",
        "--bind-tcp=localhost:9999",
        "--no-notifications",
        "--no-daemon",
        "--no-mdns",
        NULL
    };

    pid = fork();
    if (pid == 0) {
        if (execvp("xpra", args) != 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not start xpra server");
            return -1;
        }

        return 0;
    } else if (pid > 0) {
        sleep(5);

        if (sd_channel_init_from_host(&xpra_channel,
                    "localhost", "9999", SD_CHANNEL_TYPE_TCP) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not initialize xpra connection");
            return -1;
        }

        if (sd_channel_connect(&xpra_channel) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not connect to xpra service");
            return -1;
        }

        if (sd_channel_relay(channel, xpra_channel.fd) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not relay xpra data");
            return -1;
        }
    } else {
        return -1;
    }

    kill(pid, SIGKILL);

    return 0;
}

static int handle(struct sd_channel *channel,
        const struct sd_service_parameter *params, size_t nparams)
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

    if (sd_server_init(&server, "localhost", NULL, SD_CHANNEL_TYPE_TCP) < 0) {
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

    len = snprintf(NULL, 0, "tcp:localhost:%5s:100", port);
    args[2] = malloc(len);
    len = snprintf(args[2], len, "tcp:localhost:%5s:100", port);

    printf("Connecting to %s\n", args[2]);

    sleep(5);

    pid = fork();
    if (pid == 0) {
        sleep(1);

        if (execvp("xpra", args) != 0) {
            sd_log(LOG_LEVEL_ERROR, "Unable to execute xpra client");
            return -1;
        }

        return 0;
    } else if (pid > 0) {
        if (sd_server_accept(&server, &xpra_channel) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not accept xpra relay socket connection");
            return -1;
        }

        sd_log(LOG_LEVEL_VERBOSE, "Received xpra connection");

        if (sd_channel_relay(channel, xpra_channel.fd) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not relay xpra socket");
            return -1;
        }

        sd_log(LOG_LEVEL_VERBOSE, "Xpra session terminated");
    } else {
        return -1;
    }

    UNUSED(params);
    UNUSED(nparams);

    kill(pid, SIGKILL);
    sd_log(LOG_LEVEL_VERBOSE, "Terminated xpra");
    free(args[2]);

    return 0;
}

int sd_xpra_init_service(struct sd_service *service)
{
    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}
