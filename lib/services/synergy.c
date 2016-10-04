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
#include <stdio.h>

#include "capone/common.h"
#include "capone/log.h"
#include "capone/service.h"
#include "capone/socket.h"

#include "capone/services/synergy.h"

static int invoke(struct cpn_channel *channel,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
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

    UNUSED(session);
    UNUSED(cfg);

    if (cpn_channel_init_from_host(&synergy_channel, "127.0.0.1", 34589, CPN_CHANNEL_TYPE_TCP) < 0) {
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
            cpn_log(LOG_LEVEL_ERROR, "Could not connect to local synergy socket");
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
        const struct cpn_sign_pk *invoker,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    struct cpn_socket socket;
    struct cpn_channel synergy_channel;
    char *args[] = {
        "synergyc",
        "--no-daemon",
        "--no-restart",
        "--name",
        "client",
        NULL,
        NULL
    };
    uint32_t port;
    int len, pid;

    UNUSED(cfg);
    UNUSED(session);
    UNUSED(invoker);

    if (cpn_socket_init(&socket, "127.0.0.1", 0, CPN_CHANNEL_TYPE_TCP) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initialize synergy relay socket");
        return -1;
    }

    if (cpn_socket_listen(&socket) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not listen on synergy relay socket");
        return -1;
    }

    if (cpn_socket_get_address(&socket, NULL, 0, &port) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not retrieve address of synergy relay socket");
        return -1;
    }

    len = snprintf(NULL, 0, "127.0.0.1:%"PRIu32, port) + 1;
    args[5] = malloc(len);
    len = snprintf(args[5], len, "127.0.0.1:%"PRIu32, port);

    pid = fork();
    if (pid == 0) {
        if (execvp("synergyc", args) != 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to execute synergy client");
            _exit(-1);
        }

        _exit(0);
    } else if (pid > 0) {
        if (cpn_socket_accept(&socket, &synergy_channel) < 0) {
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

    cpn_socket_close(&socket);
    cpn_channel_close(&synergy_channel);

    kill(pid, SIGKILL);
    cpn_log(LOG_LEVEL_VERBOSE, "Terminated synergy");
    free(args[5]);

    return 0;
}

int cpn_synergy_init_service(const struct cpn_service_plugin **out)
{
    static struct cpn_service_plugin plugin = {
        "Input",
        "synergy",
        1,
        handle,
        invoke,
        NULL,
        NULL
    };

    *out = &plugin;

    return 0;
}

