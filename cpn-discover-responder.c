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

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>

#include "capone/common.h"
#include "capone/global.h"
#include "capone/log.h"
#include "capone/opts.h"
#include "capone/server.h"
#include "capone/service.h"
#include "capone/socket.h"

#include "capone/proto/discovery.pb-c.h"

static struct cpn_service *services;
static int numservices;

static struct cpn_sign_key_pair sign_keys;
static const char *name;
#define LISTEN_PORT "6667"

static int announce(struct cpn_channel *channel,
        DiscoverMessage *msg)
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
        if (memcmp(msg->known_keys[i].data, sign_keys.pk.data, sizeof(struct cpn_sign_key_public)))
            continue;
        cpn_log(LOG_LEVEL_DEBUG, "Skipping announce due to alreay being known");
        err = 0;
        goto out;
    }

    announce_message.name = (char *) name;
    announce_message.version = VERSION;
    announce_message.sign_key.data = sign_keys.pk.data;
    announce_message.sign_key.len = sizeof(sign_keys.pk.data);

    service_messages = malloc(sizeof(AnnounceMessage__Service *) * numservices);
    for (i = 0; i < (size_t) numservices; i++) {
        service_messages[i] = malloc(sizeof(AnnounceMessage__Service));
        announce_message__service__init(service_messages[i]);
        service_messages[i]->name = services[i].name;
        service_messages[i]->port = services[i].port;
        service_messages[i]->category = (char *) services[i].plugin->category;
    }
    announce_message.services = service_messages;
    announce_message.n_services = numservices;

    if (cpn_channel_write_protobuf(channel, &announce_message.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not write announce message");
        goto out;
    }

    cpn_log(LOG_LEVEL_DEBUG, "Sent announce");
    err = 0;

out:
    if (service_messages) {
        for (i = 0; i < (size_t) numservices; i++)
            free(service_messages[i]);
        free(service_messages);
    }
    return err;
}

static void handle_udp(struct cpn_channel *channel)
{
    DiscoverMessage *msg = NULL;
    struct cpn_channel client_channel;
    char host[128], port[16];
    int ret;

    if (cpn_channel_receive_protobuf(channel, &discover_message__descriptor,
            (ProtobufCMessage **) &msg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive envelope");
        goto out;
    }

    cpn_log(LOG_LEVEL_DEBUG, "Received discovery message");

    if ((ret = getnameinfo((struct sockaddr *) &channel->addr, channel->addrlen,
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

    if (announce(&client_channel, msg) < 0)
        cpn_log(LOG_LEVEL_ERROR, "Could not announce message");

    if (cpn_channel_close(&client_channel) < 0)
        cpn_log(LOG_LEVEL_ERROR, "Could not close client channel");

out:
    if (msg)
        discover_message__free_unpacked(msg, NULL);
}

static void handle_tcp(struct cpn_channel *channel)
{
    struct cpn_sign_key_public remote_sign_key;
    DiscoverMessage *msg = NULL;

    if (cpn_server_await_encryption(channel, &sign_keys, &remote_sign_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to await encryption");
        goto out;
    }

    if (cpn_channel_receive_protobuf(channel, &discover_message__descriptor,
            (ProtobufCMessage **) &msg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive envelope");
        goto out;
    }

    cpn_log(LOG_LEVEL_DEBUG, "Received directed discovery");

    announce(channel, msg);

out:
    cpn_channel_close(channel);
    if (msg)
        discover_message__free_unpacked(msg, NULL);
}

static void handle_connections()
{
    struct cpn_socket udp_socket, tcp_socket;
    struct cpn_channel channel;
    fd_set fds;
    int nfds;

    if (cpn_socket_init(&udp_socket, NULL, LISTEN_PORT, CPN_CHANNEL_TYPE_UDP) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to init listening channel");
        return;
    }

    if (cpn_socket_init(&tcp_socket, NULL, LISTEN_PORT, CPN_CHANNEL_TYPE_TCP) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to init listening channel");
        return;
    }
    if (cpn_socket_listen(&tcp_socket) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to listen on TCP channel");
        return;
    }

    nfds = MAX(udp_socket.fd, tcp_socket.fd) + 1;

    while (true) {
        FD_ZERO(&fds);
        FD_SET(udp_socket.fd, &fds);
        FD_SET(tcp_socket.fd, &fds);

        if (select(nfds, &fds, NULL, NULL, NULL) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to select on channels");
            continue;
        }

        if (FD_ISSET(udp_socket.fd, &fds)) {
            if (cpn_socket_accept(&udp_socket, &channel) < 0) {
                cpn_log(LOG_LEVEL_ERROR, "Unable to accept UDP connection");
                continue;
            }
            handle_udp(&channel);
        }

        if (FD_ISSET(tcp_socket.fd, &fds)) {
            if (cpn_socket_accept(&tcp_socket, &channel) < 0) {
                cpn_log(LOG_LEVEL_ERROR, "Unable to accept TCP connection");
                continue;
            }
            handle_tcp(&channel);
        }
    }
}

int main(int argc, const char *argv[])
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('c', "--config",
                "Path to configuration file", "CFGFILE", false),
        CPN_OPTS_OPT_END,
    };
    struct cpn_cfg cfg;

    if (cpn_global_init() < 0)
        return -1;

    if (cpn_opts_parse_cmd(opts, argc, argv) < 0) {
        return -1;
    }

    if (cpn_cfg_parse(&cfg, opts[0].value.string) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to read configuration");
        return -1;
    }

    if ((name = cpn_cfg_get_str_value(&cfg, "core", "name")) == NULL) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to read server name");
        return -1;
    }

    if (cpn_sign_key_pair_from_config(&sign_keys, &cfg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to read local keys");
        return -1;
    }

    if ((numservices = cpn_services_from_config(&services, &cfg)) <= 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to read service configuration");
        return -1;
    }


    handle_connections();

    return 0;
}
