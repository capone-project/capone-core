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

#include "capone/acl.h"
#include "capone/common.h"
#include "capone/global.h"
#include "capone/log.h"
#include "capone/opts.h"
#include "capone/server.h"
#include "capone/service.h"
#include "capone/socket.h"

struct handle_connection_args {
    const struct cpn_cfg *cfg;
    const struct cpn_service *service;
    struct cpn_channel channel;
};

static struct cpn_acl request_acl = CPN_ACL_INIT;
static struct cpn_acl query_acl = CPN_ACL_INIT;

static struct cpn_sign_key_pair local_keys;
static struct cpn_service service;

static int read_acl(struct cpn_acl *acl, const char *file)
{
    struct cpn_sign_key_public pk;
    FILE *stream = NULL;
    char *line = NULL;
    size_t length;
    ssize_t read;

    cpn_acl_clear(acl);

    stream = fopen(file, "r");
    if (stream == NULL)
        return -1;

    while ((read = getline(&line, &length, stream)) != -1) {
        if (line[read - 1] == '\n')
            line[read - 1] = '\0';

        if (cpn_sign_key_public_from_hex(&pk, line) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Invalid key '%s'", line);
            goto out_err;
        }

        if (cpn_acl_add_right(acl, &pk, CPN_ACL_RIGHT_EXEC) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Could not add right to ACL");
            goto out_err;
        }
    }
    free(line);
    line = NULL;

    if (!feof(stream))
        goto out_err;

    fclose(stream);

    return 0;

out_err:
    fclose(stream);
    free(line);

    return -1;
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

static void *handle_connection(void *payload)
{
    struct handle_connection_args *args = (struct handle_connection_args *) payload;
    struct cpn_sign_key_public remote_key;
    enum cpn_command type;

    if (cpn_server_await_encryption(&args->channel, &local_keys, &remote_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to negotiate encryption");
        goto out;
    }

    if (cpn_server_await_command(&type, &args->channel) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not receive connection type");
        goto out;
    }

    switch (type) {
        case CPN_COMMAND_QUERY:
            cpn_log(LOG_LEVEL_DEBUG, "Received query");

            if (!cpn_acl_is_allowed(&query_acl, &remote_key, CPN_ACL_RIGHT_EXEC)) {
                cpn_log(LOG_LEVEL_ERROR, "Received unauthorized query");
                goto out;
            }

            if (cpn_server_handle_query(&args->channel, args->service) < 0) {
                cpn_log(LOG_LEVEL_ERROR, "Received invalid query");
                goto out;
            }

            goto out;
        case CPN_COMMAND_REQUEST:
            cpn_log(LOG_LEVEL_DEBUG, "Received request");

            if (!cpn_acl_is_allowed(&request_acl, &remote_key, CPN_ACL_RIGHT_EXEC)) {
                cpn_log(LOG_LEVEL_ERROR, "Received unauthorized query");
                goto out;
            }

            if (cpn_server_handle_request(&args->channel, &remote_key, args->service->plugin) < 0) {
                cpn_log(LOG_LEVEL_ERROR, "Received invalid request");
                goto out;
            }

            goto out;
        case CPN_COMMAND_CONNECT:
            cpn_log(LOG_LEVEL_DEBUG, "Received connect");

            if (cpn_server_handle_session(&args->channel, &remote_key, args->service, args->cfg) < 0)
            {
                cpn_log(LOG_LEVEL_ERROR, "Received invalid connect");
            }

            goto out;
        case CPN_COMMAND_TERMINATE:
            cpn_log(LOG_LEVEL_DEBUG, "Received termination request");

            if (cpn_server_handle_termination(&args->channel, &remote_key) < 0) {
                cpn_log(LOG_LEVEL_ERROR, "Received invalid termination request");
            }

            goto out;
        default:
            cpn_log(LOG_LEVEL_ERROR, "Unknown connection envelope type %d", type);
            goto out;
    }

out:
    cpn_channel_close(&args->channel);
    free(payload);
    return NULL;
}

static int setup(struct cpn_cfg *cfg, int argc, const char *argv[])
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('c', "--config",
                "Path to configuration file", "CFGFILE", false),
        CPN_OPTS_OPT_STRING('s', "--service",
                "Name of the service to host", "SERVICE", false),
        CPN_OPTS_OPT_STRING(0, "--request-acl",
                "Path to file containing access control list for requests",
                "FILE", false),
        CPN_OPTS_OPT_STRING(0, "--query-acl",
                "Path to file containing access control list for queries",
                "FILE", false),
        CPN_OPTS_OPT_END
    };
    int err;

    if (cpn_global_init() < 0)
        return -1;

    if (cpn_opts_parse_cmd(opts, argc, argv) < 0) {
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));

    if (cpn_cfg_parse(cfg, cpn_opts_get(opts, 'c', NULL)->string) < 0) {
        puts("Could not parse config");
        err = -1;
        goto out;
    }

    if (cpn_opts_get(opts, 0, "--request-acl")) {
        read_acl(&request_acl, cpn_opts_get(opts, 0, "request_acl")->string);
    } else {
        cpn_acl_add_wildcard(&request_acl, CPN_ACL_RIGHT_EXEC);
    }

    if (cpn_opts_get(opts, 0, "--query-acl")) {
        read_acl(&query_acl, cpn_opts_get(opts, 0, "--query-acl")->string);
    } else {
        cpn_acl_add_wildcard(&query_acl, CPN_ACL_RIGHT_EXEC);
    }

    if (setup_signals() < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not set up signal handlers");
        err = -1;
        goto out;
    }

    if (cpn_service_from_config(&service, cpn_opts_get(opts, 0, "--service")->string, cfg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not parse services");
        err = -1;
        goto out;
    }

    if (cpn_sign_key_pair_from_config(&local_keys, cfg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not parse config");
        err = -1;
        goto out;
    }

    return 0;

out:
    cpn_cfg_free(cfg);

    return err;
}

int main(int argc, const char *argv[])
{
    struct cpn_socket socket;
    struct cpn_cfg cfg;

    if (setup(&cfg, argc, argv) < 0) {
        return -1;
    }

    if (cpn_socket_init(&socket, NULL, service.port, CPN_CHANNEL_TYPE_TCP) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not set up socket");
        goto out;
    }

    if (cpn_socket_listen(&socket) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not start listening");
        goto out;
    }

    while (1) {
        struct handle_connection_args *args = malloc(sizeof(*args));;

        if (cpn_socket_accept(&socket, &args->channel) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Could not accept connection");
            goto out;
        }

        args->cfg = &cfg;
        args->service = &service;

        cpn_spawn(NULL, handle_connection, args);
    }

out:
    cpn_socket_close(&socket);
    cpn_cfg_free(&cfg);

    return -1;
}
