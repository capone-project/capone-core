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

#include <string.h>

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sodium.h>

#include "lib/common.h"
#include "lib/log.h"
#include "lib/proto.h"
#include "lib/server.h"
#include "lib/service.h"

static struct sd_sign_key_public *whitelistkeys;
static uint32_t nwhitelistkeys;

static struct sd_sign_key_pair local_keys;
static struct sd_service service;

static struct sd_service_session *sessions = NULL;

static int read_whitelist(struct sd_sign_key_public **out, const char *file)
{
    struct sd_sign_key_public *keys = NULL;
    FILE *stream = NULL;
    char *line = NULL;
    size_t nkeys = 0, length;
    ssize_t read;

    *out = NULL;

    stream = fopen(file, "r");
    if (stream == NULL)
        return -1;

    while ((read = getline(&line, &length, stream)) != -1) {
        if (line[read - 1] == '\n')
            line[read - 1] = '\0';

        keys = realloc(keys, sizeof(struct sd_sign_key_public) * ++nkeys);
        if (sd_sign_key_public_from_hex(&keys[nkeys - 1], line) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Invalid key '%s'", line);
            return -1;
        }
    }
    free(line);

    if (!feof(stream)) {
        fclose(stream);
        free(keys);
        return -1;
    }

    fclose(stream);
    *out = keys;

    return nkeys;
}

static void
sigchild_handler(int sig)
{
    int status;
    UNUSED(sig);
    while (waitpid(-1, &status, WNOHANG) > 0);
}

static void
exit_handler(int sig)
{
    kill(0, sig);
    exit(0);
}

static int setup_signals(void)
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = sigchild_handler;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = exit_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGKILL, &sa, NULL);

    return 0;
}

int main(int argc, char *argv[])
{
    const char *config, *servicename;
    struct sd_server server;
    struct sd_channel channel;
    int ret;

    if (argc < 3 || argc > 4) {
        printf("USAGE: %s <CONFIG> <SERVICENAME> [<CLIENT_WHITELIST>]\n", argv[0]);
        return -1;
    }

    config = argv[1];
    servicename = argv[2];

    if (argc == 4) {
        ret = read_whitelist(&whitelistkeys, argv[3]);
        if (ret < 0) {
            puts("Could not read client whitelist");
            return -1;
        }
        nwhitelistkeys = ret;

        sd_log(LOG_LEVEL_VERBOSE, "Read %d keys from whitelist", nwhitelistkeys);
    }

    if (setup_signals() < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not set up signal handlers");
        return -1;
    }

    if (sodium_init() < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not init libsodium");
        return -1;
    }

    if (sd_service_from_config_file(&service, servicename, config) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not parse services");
        return -1;
    }

    if (sd_sign_key_pair_from_config_file(&local_keys, config) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not parse config");
        return -1;
    }

    if (sd_server_init(&server, NULL, service.port, SD_CHANNEL_TYPE_TCP) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not set up server");
        return -1;
    }

    if (sd_server_listen(&server) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not start listening");
        return -1;
    }

    while (1) {
        enum sd_connection_type type;
        struct sd_service_session *session;

        if (sd_server_accept(&server, &channel) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not accept connection");
            return -1;
        }

        if (sd_proto_receive_connection_type(&type, &channel) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not receive connection type");
            return -1;
        }

        switch (type) {
            case SD_CONNECTION_TYPE_QUERY:
                sd_log(LOG_LEVEL_DEBUG, "Received query");

                if (sd_proto_answer_query(&channel,
                            &service, &local_keys, whitelistkeys, nwhitelistkeys) < 0)
                {
                    sd_log(LOG_LEVEL_ERROR, "Received invalid query");
                }

                sd_channel_close(&channel);
                break;
            case SD_CONNECTION_TYPE_REQUEST:
                sd_log(LOG_LEVEL_DEBUG, "Received request");

                if (sd_proto_answer_request(&session,
                            &channel, &local_keys, whitelistkeys, nwhitelistkeys) < 0)
                {
                    sd_log(LOG_LEVEL_ERROR, "Received invalid request");
                } else {
                    session->next = sessions;
                    sessions = session;
                }

                sd_channel_close(&channel);
                break;
            case SD_CONNECTION_TYPE_CONNECT:
                sd_log(LOG_LEVEL_DEBUG, "Received connect");
                sd_proto_handle_session(&channel, &service, sessions);
                break;
            default:
                sd_log(LOG_LEVEL_ERROR, "Unknown connection envelope type %d", type);
                break;
        }
    }

    sd_server_close(&server);

    return 0;
}
