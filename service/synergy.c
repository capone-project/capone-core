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

#include "capone/common.h"
#include "capone/log.h"
#include "capone/server.h"
#include "capone/service.h"

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct cpn_parameter **out)
{
    *out = NULL;
    return 0;
}

static int invoke(struct cpn_channel *channel, int argc, char **argv)
{
    struct cpn_channel synergy_channel;
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

    if (cpn_channel_init_from_host(&synergy_channel, "127.0.0.1", "34589", CPN_CHANNEL_TYPE_TCP) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initialize local synergy channel");
        return -1;
    }

    pid = fork();
    if (pid == 0) {
        if (execvp("synergys", args) != 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to execute synergy client");
            _exit(-1);
        }

        _exit(0);
    } else if (pid > 0) {
        /* TODO: get better workaround to know synergys has * started */
        sleep(1);

        if ((err = cpn_channel_connect(&synergy_channel)) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Could not connect to local synergy server");
            goto out;
        }

        if ((err = cpn_channel_relay(channel, 1, synergy_channel.fd)) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Could not relay synergy socket");
            goto out;
        }
    } else {
        return -1;
    }

out:
    cpn_channel_close(&synergy_channel);
    kill(pid, SIGKILL);
    cpn_log(LOG_LEVEL_VERBOSE, "Terminated synergy");

    return err;
}

static int handle(struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    struct cpn_server server;
    struct cpn_channel synergy_channel;
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

    if (cpn_server_init(&server, "127.0.0.1", NULL, CPN_CHANNEL_TYPE_TCP) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initialize synergy relay socket");
        return -1;
    }

    if (cpn_server_listen(&server) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not listen on synergy relay socket");
        return -1;
    }

    if (cpn_server_get_address(&server, NULL, 0, port, sizeof(port)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not retrieve address of synergy relay socket");
        return -1;
    }

    len = snprintf(NULL, 0, "127.0.0.1:%5s", port) + 1;
    args[5] = malloc(len);
    len = snprintf(args[5], len, "127.0.0.1:%5s", port);

    pid = fork();
    if (pid == 0) {
        if (execvp("synergyc", args) != 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to execute synergy client");
            _exit(-1);
        }

        _exit(0);
    } else if (pid > 0) {
        if (cpn_server_accept(&server, &synergy_channel) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Could not accept synergy relay socket connection");
            return -1;
        }

        if (cpn_channel_relay(channel, 1, synergy_channel.fd) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Could not relay synergy socket");
            return -1;
        }
    } else {
        return -1;
    }

    cpn_server_close(&server);
    cpn_channel_close(&synergy_channel);

    kill(pid, SIGKILL);
    cpn_log(LOG_LEVEL_VERBOSE, "Terminated synergy");
    free(args[5]);

    return 0;
}

int cpn_synergy_init_service(struct cpn_service *service)
{
    service->category = "Input";
    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}

