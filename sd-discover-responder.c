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

#include <sodium.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>

#include "lib/common.h"
#include "lib/log.h"
#include "lib/proto.h"
#include "lib/server.h"
#include "lib/service.h"

#include "proto/discovery.pb-c.h"

static AnnounceMessage announce_message;
static struct sd_sign_key_pair sign_keys;

#define LISTEN_PORT "6667"

static void announce(struct sd_channel *channel)
{
    if (sd_channel_write_protobuf(channel, &announce_message.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not write announce message");
        return;
    }

    sd_log(LOG_LEVEL_DEBUG, "Sent announce");
}

static void handle_udp(struct sd_channel *channel)
{
    DiscoverMessage *discover = NULL;
    struct sd_channel client_channel;
    char host[128], port[16];
    int ret;

    if (sd_channel_receive_protobuf(channel, &discover_message__descriptor,
            (ProtobufCMessage **) &discover) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive envelope");
        goto out;
    }

    sd_log(LOG_LEVEL_DEBUG, "Received discovery message");

    if ((ret = getnameinfo((struct sockaddr *) &channel->addr, channel->addrlen,
                host, sizeof(host), NULL, 0, NI_NUMERICHOST)) != 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Could not extract address: %s",
                gai_strerror(ret));
        goto out;
    }
    snprintf(port, sizeof(port), "%u", discover->port);

    if (sd_channel_init_from_host(&client_channel, host, port, SD_CHANNEL_TYPE_UDP) < 0) {
        sd_log(LOG_LEVEL_ERROR,"Could not initialize client channel");
        goto out;
    }

    announce(&client_channel);

    if (sd_channel_close(&client_channel) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not close client channel");
    }

out:
    if (discover)
        discover_message__free_unpacked(discover, NULL);
}

static void handle_tcp(struct sd_channel *channel)
{
    struct sd_sign_key_public remote_sign_key;

    if (sd_proto_await_encryption(channel, &sign_keys, &remote_sign_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to await encryption");
        goto out;
    }

    sd_log(LOG_LEVEL_DEBUG, "Received directed discovery");

    announce(channel);

out:
    sd_channel_close(channel);
}

static void handle_connections()
{
    struct sd_server udp_server, tcp_server;
    struct sd_channel channel;
    fd_set fds;
    int nfds;

    if (sd_server_init(&udp_server, NULL, LISTEN_PORT, SD_CHANNEL_TYPE_UDP) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to init listening channel");
        return;
    }

    if (sd_server_init(&tcp_server, NULL, LISTEN_PORT, SD_CHANNEL_TYPE_TCP) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to init listening channel");
        return;
    }
    if (sd_server_listen(&tcp_server) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to listen on TCP channel");
        return;
    }

    nfds = MAX(udp_server.fd, tcp_server.fd) + 1;

    while (true) {
        FD_ZERO(&fds);
        FD_SET(udp_server.fd, &fds);
        FD_SET(tcp_server.fd, &fds);

        if (select(nfds, &fds, NULL, NULL, NULL) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Unable to select on channels");
            continue;
        }

        if (FD_ISSET(udp_server.fd, &fds)) {
            if (sd_server_accept(&udp_server, &channel) < 0) {
                sd_log(LOG_LEVEL_ERROR, "Unable to accept UDP connection");
                continue;
            }
            handle_udp(&channel);
        }

        if (FD_ISSET(tcp_server.fd, &fds)) {
            if (sd_server_accept(&tcp_server, &channel) < 0) {
                sd_log(LOG_LEVEL_ERROR, "Unable to accept TCP connection");
                continue;
            }
            handle_tcp(&channel);
        }
    }
}

int main(int argc, char *argv[])
{
    AnnounceMessage__Service **service_messages;
    struct sd_service *services;
    int i, numservices;

    if (sodium_init() < 0) {
        return -1;
    }

    if (argc != 2) {
        printf("USAGE: %s <SERVER_CONFIG>\n", argv[0]);
        return 0;
    }

    if (sd_sign_key_pair_from_config_file(&sign_keys, argv[1]) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to read local keys");
        return -1;
    }

    if ((numservices = sd_services_from_config_file(&services, argv[1])) <= 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to read service configuration");
        return -1;
    }

    announce_message__init(&announce_message);
    announce_message.version = VERSION;
    announce_message.sign_key.data = sign_keys.pk.data;
    announce_message.sign_key.len = sizeof(sign_keys.pk.data);

    service_messages = malloc(sizeof(AnnounceMessage__Service *) * numservices);
    for (i = 0; i < numservices; i++) {
        AnnounceMessage__Service *service_message = malloc(sizeof(AnnounceMessage__Service));
        announce_message__service__init(service_message);

        service_message->name = services[i].name;
        service_message->category = services[i].category;
        service_message->port = services[i].port;

        service_messages[i] = service_message;
    }
    announce_message.services = service_messages;
    announce_message.n_services = numservices;

    handle_connections();

    return 0;
}
