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

#include "synergy.h"

#include "lib/common.h"
#include "lib/log.h"
#include "lib/server.h"
#include "lib/service.h"

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct sd_parameter **out)
{
    *out = NULL;
    return 0;
}

static int invoke(struct sd_channel *channel, int argc, char **argv)
{
    struct sd_channel synergy_channel;
    char *args[] = {
        "synergys",
        "--address",
        "localhost:34589",
        "--no-daemon",
        "--no-restart",
        "--name",
        "server",
        NULL
    };
    int pid, err;

    UNUSED(argc);
    UNUSED(argv);

    if (sd_channel_init_from_host(&synergy_channel, "127.0.0.1", "34589", SD_CHANNEL_TYPE_TCP) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not initialize local synergy channel");
        return -1;
    }

    pid = fork();
    if (pid == 0) {
        if (execvp("synergys", args) != 0) {
            sd_log(LOG_LEVEL_ERROR, "Unable to execute synergy client");
            _exit(-1);
        }

        _exit(0);
    } else if (pid > 0) {
        /* TODO: get better workaround to know synergys has * started */
        sleep(1);

        if ((err = sd_channel_connect(&synergy_channel)) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not connect to local synergy server");
            goto out;
        }

        if ((err = sd_channel_relay(channel, 1, synergy_channel.fd)) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not relay synergy socket");
            goto out;
        }
    } else {
        return -1;
    }

out:
    sd_channel_close(&synergy_channel);
    kill(pid, SIGKILL);
    sd_log(LOG_LEVEL_VERBOSE, "Terminated synergy");

    return err;
}

static int handle(struct sd_channel *channel,
        const struct sd_sign_key_public *invoker,
        const struct sd_session *session,
        const struct sd_cfg *cfg)
{
    struct sd_server server;
    struct sd_channel synergy_channel;
    char port[10], *args[] = {
        "synergyc",
        "--no-daemon",
        "--no-restart",
        "--name",
        "client",
        NULL,
        NULL
    };
    int len, pid;

    UNUSED(cfg);
    UNUSED(session);
    UNUSED(invoker);

    if (sd_server_init(&server, "127.0.0.1", NULL, SD_CHANNEL_TYPE_TCP) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not initialize synergy relay socket");
        return -1;
    }

    if (sd_server_listen(&server) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not listen on synergy relay socket");
        return -1;
    }

    if (sd_server_get_address(&server, NULL, 0, port, sizeof(port)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not retrieve address of synergy relay socket");
        return -1;
    }

    len = snprintf(NULL, 0, "127.0.0.1:%5s", port) + 1;
    args[5] = malloc(len);
    len = snprintf(args[5], len, "127.0.0.1:%5s", port);

    pid = fork();
    if (pid == 0) {
        if (execvp("synergyc", args) != 0) {
            sd_log(LOG_LEVEL_ERROR, "Unable to execute synergy client");
            _exit(-1);
        }

        _exit(0);
    } else if (pid > 0) {
        if (sd_server_accept(&server, &synergy_channel) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not accept synergy relay socket connection");
            return -1;
        }

        if (sd_channel_relay(channel, 1, synergy_channel.fd) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not relay synergy socket");
            return -1;
        }
    } else {
        return -1;
    }

    sd_server_close(&server);
    sd_channel_close(&synergy_channel);

    kill(pid, SIGKILL);
    sd_log(LOG_LEVEL_VERBOSE, "Terminated synergy");
    free(args[5]);

    return 0;
}

int sd_synergy_init_service(struct sd_service *service)
{
    service->category = "Input";
    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}

