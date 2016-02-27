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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sodium.h>

#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>

#include "lib/common.h"
#include "lib/log.h"
#include "lib/server.h"
#include "lib/service.h"

#include "proto/discovery.pb-c.h"

static AnnounceMessage announce_message;
static struct sd_sign_key_public local_key;

#define LISTEN_PORT 6667

static void announce(struct sockaddr_storage addr, uint32_t port)
{
    struct sd_channel channel;
    char host[128], service[16];

    if (getnameinfo((struct sockaddr *) &addr, sizeof(addr),
                host, sizeof(host), NULL, 0, 0) != 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not extract address");
        return;
    }
    snprintf(service, sizeof(service), "%u", port);

    if (sd_channel_init_from_host(&channel, host, service, SD_CHANNEL_TYPE_UDP) < 0) {
        puts("Could not initialize channel");
        return;
    }

    if (sd_channel_write_protobuf(&channel, &announce_message.base) < 0) {
        puts("Could not write announce message");
        return;
    }

    puts("Sent announce");

    sd_channel_close(&channel);
}

static void handle_discover()
{
    struct sd_server server;
    struct sd_channel channel;
    DiscoverMessage *discover;

    if (sd_server_init(&server, NULL, "6667", SD_CHANNEL_TYPE_UDP) < 0) {
        puts("Unable to init listening channel");
        return;
    }

    while (true) {
        waitpid(-1, NULL, WNOHANG);

        if (sd_server_accept(&server, &channel) < 0) {
            puts("Unable to accept connection");
            goto out;
        }

        if (sd_channel_receive_protobuf(&channel, &discover_message__descriptor,
                (ProtobufCMessage **) &discover) < 0) {
            puts("Unable to receive envelope");
            goto out;
        }

        sd_log(LOG_LEVEL_DEBUG, "Received discovery message");

        announce(channel.addr, discover->port);

        discover_message__free_unpacked(discover, NULL);
    }

out:
    sd_server_close(&server);
}

int main(int argc, char *argv[])
{
    AnnounceMessage__Service **service_messages;
    struct sd_service *services;
    struct sd_sign_key_pair keys;
    int i, numservices;

    if (sodium_init() < 0) {
        return -1;
    }

    if (argc != 2) {
        printf("USAGE: %s <SERVER_CONFIG>\n", argv[0]);
        return 0;
    }

    if (sd_sign_key_pair_from_config_file(&keys, argv[1]) < 0) {
        puts("Unable to read local keys");
        return -1;
    }
    memcpy(&local_key.data, &keys.pk.data, sizeof(local_key.data));
    sodium_memzero(&keys, sizeof(keys));

    if ((numservices = sd_services_from_config_file(&services, argv[1])) <= 0) {
        puts("Unable to read service configuration");
        return -1;
    }

    announce_message__init(&announce_message);
    announce_message.version = VERSION;
    announce_message.sign_key.data = local_key.data;
    announce_message.sign_key.len = sizeof(local_key.data);

    service_messages = malloc(sizeof(AnnounceMessage__Service *) * numservices);
    for (i = 0; i < numservices; i++) {
        AnnounceMessage__Service *service_message = malloc(sizeof(AnnounceMessage__Service));
        announce_message__service__init(service_message);

        service_message->name = services[i].name;
        service_message->type = services[i].type;
        service_message->port = services[i].port;

        service_messages[i] = service_message;
    }
    announce_message.services = service_messages;
    announce_message.n_services = numservices;

    handle_discover();

    return 0;
}
