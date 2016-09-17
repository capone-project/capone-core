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
#include <sys/select.h>
#include <netdb.h>

#include "capone/acl.h"
#include "capone/common.h"
#include "capone/global.h"
#include "capone/log.h"
#include "capone/opts.h"
#include "capone/server.h"
#include "capone/service.h"
#include "capone/socket.h"

#include "capone/proto/discovery.pb-c.h"

#define LISTEN_PORT "6667"

struct handle_connection_args {
    const struct cpn_cfg *cfg;
    const struct cpn_service *service;
    struct cpn_channel channel;
};

struct handle_discovery_args {
    struct cpn_channel channel;
    int nservices;
    struct cpn_service *services;
};

static struct cpn_acl request_acl = CPN_ACL_INIT;
static struct cpn_acl query_acl = CPN_ACL_INIT;

static struct cpn_sign_key_pair local_keys;
static const char *name;

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

static int announce(struct cpn_channel *channel,
        DiscoverMessage *msg,
        int nservices, struct cpn_service *services)
{
    AnnounceMessage announce_message = ANNOUNCE_MESSAGE__INIT;
    AnnounceMessage__Service **service_messages = NULL;
    size_t i;
    int err = -1;

    if (strcmp(msg->version, VERSION)) {
        cpn_log(LOG_LEVEL_ERROR, "Cannot handle announce message version %s",
                msg->version);
        goto out;
    }

    for (i = 0; i < msg->n_known_keys; i++) {
        if (msg->known_keys[i].len != sizeof(struct cpn_sign_key_public))
            continue;
        if (memcmp(msg->known_keys[i].data, local_keys.pk.data, sizeof(struct cpn_sign_key_public)))
            continue;
        cpn_log(LOG_LEVEL_DEBUG, "Skipping announce due to alreay being known");
        err = 0;
        goto out;
    }

    announce_message.name = (char *) name;
    announce_message.version = VERSION;
    announce_message.sign_key.data = local_keys.pk.data;
    announce_message.sign_key.len = sizeof(local_keys.pk.data);

    service_messages = malloc(sizeof(AnnounceMessage__Service *) * nservices);
    for (i = 0; i < (size_t) nservices; i++) {
        service_messages[i] = malloc(sizeof(AnnounceMessage__Service));
        announce_message__service__init(service_messages[i]);
        service_messages[i]->name = services[i].name;
        service_messages[i]->port = services[i].port;
        service_messages[i]->category = (char *) services[i].plugin->category;
    }
    announce_message.services = service_messages;
    announce_message.n_services = nservices;

    if (cpn_channel_write_protobuf(channel, &announce_message.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not write announce message");
        goto out;
    }

    cpn_log(LOG_LEVEL_DEBUG, "Sent announce");
    err = 0;

out:
    if (service_messages) {
        for (i = 0; i < (size_t) nservices; i++)
            free(service_messages[i]);
        free(service_messages);
    }

    return err;
}

static void *handle_discovery_udp(void *payload)
{
    struct handle_discovery_args *args = (struct handle_discovery_args *) payload;
    DiscoverMessage *msg = NULL;
    struct cpn_channel client_channel;
    char host[128], port[16];
    int ret;

    client_channel.fd = -1;

    if (cpn_channel_receive_protobuf(&args->channel, &discover_message__descriptor,
            (ProtobufCMessage **) &msg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive envelope");
        goto out;
    }

    cpn_log(LOG_LEVEL_DEBUG, "Received discovery message");

    if ((ret = getnameinfo((struct sockaddr *) &args->channel.addr, args->channel.addrlen,
                host, sizeof(host), NULL, 0, NI_NUMERICHOST)) != 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Could not extract address: %s",
                gai_strerror(ret));
        goto out;
    }
    snprintf(port, sizeof(port), "%u", msg->port);

    if (cpn_channel_init_from_host(&client_channel, host, port, CPN_CHANNEL_TYPE_UDP) < 0) {
        cpn_log(LOG_LEVEL_ERROR,"Could not initialize client channel");
        goto out;
    }

    if (announce(&client_channel, msg, args->nservices, args->services) < 0)
        cpn_log(LOG_LEVEL_ERROR, "Could not announce message");

    if (cpn_channel_close(&client_channel) < 0)
        cpn_log(LOG_LEVEL_ERROR, "Could not close client channel");

out:
    if (client_channel.fd >= 0)
        cpn_channel_close(&client_channel);
    if (msg)
        discover_message__free_unpacked(msg, NULL);
    free(payload);

    return NULL;
}

static void *handle_discovery_tcp(void *payload)
{
    struct handle_discovery_args *args = (struct handle_discovery_args *) payload;
    struct cpn_sign_key_public remote_sign_key;
    DiscoverMessage *msg = NULL;

    if (cpn_server_await_encryption(&args->channel, &local_keys, &remote_sign_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to await encryption");
        goto out;
    }

    if (cpn_channel_receive_protobuf(&args->channel, &discover_message__descriptor,
            (ProtobufCMessage **) &msg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive envelope");
        goto out;
    }

    cpn_log(LOG_LEVEL_DEBUG, "Received directed discovery");

    if (announce(&args->channel, msg, args->nservices, args->services) < 0)
        cpn_log(LOG_LEVEL_ERROR, "Could not announce message");

out:
    cpn_channel_close(&args->channel);
    if (msg)
        discover_message__free_unpacked(msg, NULL);
    free(payload);

    return NULL;
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
        CPN_OPTS_OPT_STRING(0, "--request-acl",
                "Path to file containing access control list for requests",
                "FILE", true),
        CPN_OPTS_OPT_STRING(0, "--query-acl",
                "Path to file containing access control list for queries",
                "FILE", true),
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

    if (cpn_sign_key_pair_from_config(&local_keys, cfg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not parse config");
        err = -1;
        goto out;
    }

    if ((name = cpn_cfg_get_str_value(cfg, "core", "name")) == NULL) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to read server name");
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
    struct cpn_service *services;
    struct cpn_socket *sockets;
    struct cpn_socket udp_socket, tcp_socket;
    struct cpn_cfg cfg;
    uint32_t i, n;

    if (setup(&cfg, argc, argv) < 0) {
        return -1;
    }

    n = cpn_services_from_config(&services, &cfg);
    sockets = malloc(sizeof(struct cpn_socket) * n);

    if (cpn_socket_init(&udp_socket, NULL, LISTEN_PORT, CPN_CHANNEL_TYPE_UDP) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to init listening channel");
        goto out;
    }

    if (cpn_socket_init(&tcp_socket, NULL, LISTEN_PORT, CPN_CHANNEL_TYPE_TCP) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to init listening channel");
        goto out;
    }
    if (cpn_socket_listen(&tcp_socket) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to listen on TCP channel");
        goto out;
    }

    for (i = 0; i < n; i++) {
        if (cpn_socket_init(&sockets[i], NULL, services[i].port, CPN_CHANNEL_TYPE_TCP) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Could not set up socket");
            goto out;
        }

        if (cpn_socket_listen(&sockets[i]) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Could not start listening");
            goto out;
        }
    }

    while (1) {
        fd_set fds = { 0 };
        int maxfd = -1;

        FD_SET(tcp_socket.fd, &fds);
        maxfd = MAX(maxfd, tcp_socket.fd);
        FD_SET(udp_socket.fd, &fds);
        maxfd = MAX(maxfd, udp_socket.fd);

        for (i = 0; i < n; i++) {
            FD_SET(sockets[i].fd, &fds);
            maxfd = MAX(maxfd, sockets[i].fd);
        }

        if (select(maxfd + 1, &fds, NULL, NULL, NULL) == -1)
            continue;

        if (FD_ISSET(tcp_socket.fd, &fds)) {
            struct handle_discovery_args *args = malloc(sizeof(*args));
            args->nservices = n;
            args->services = services;
            if (cpn_socket_accept(&tcp_socket, &args->channel) < 0) {
                free(args);
            } else {
                cpn_spawn(NULL, handle_discovery_tcp, args);
            }
        }

        if (FD_ISSET(udp_socket.fd, &fds)) {
            struct handle_discovery_args *args = malloc(sizeof(*args));
            args->nservices = n;
            args->services = services;
            if (cpn_socket_accept(&udp_socket, &args->channel) < 0) {
                free(args);
            } else {
                cpn_spawn(NULL, handle_discovery_udp, args);
            }
        }

        for (i = 0; i < n; i++) {
            struct handle_connection_args *args;

            if (!FD_ISSET(sockets[i].fd, &fds))
                continue;

            args = malloc(sizeof(*args));;

            if (cpn_socket_accept(&sockets[i], &args->channel) < 0) {
                cpn_log(LOG_LEVEL_ERROR, "Could not accept connection");
                goto out;
            }

            args->cfg = &cfg;
            args->service = &services[i];

            cpn_spawn(NULL, handle_connection, args);
        }
    }

out:
    for (i = 0; i < n; i++)
        cpn_socket_close(&sockets[i]);
    cpn_cfg_free(&cfg);
    free(services);
    free(sockets);

    return -1;
}
