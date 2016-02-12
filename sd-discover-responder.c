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
static struct sd_keys keys;

#define LISTEN_PORT 6667

static void announce(struct sockaddr_storage addr, uint32_t port)
{
    Envelope *env = NULL;

    struct sd_channel channel;
    char host[128], service[16];

    if (getnameinfo((struct sockaddr *) &addr, sizeof(addr),
                host, sizeof(host), NULL, 0, 0) != 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not extract address");
        return;
    }
    snprintf(service, sizeof(service), "%u", port);

    if (pack_signed_protobuf(&env, (ProtobufCMessage *) &announce_message, &keys, NULL) < 0) {
        puts("Could not create signed envelope");
        return;
    }

    if (sd_channel_init_from_host(&channel, host, service, SD_CHANNEL_TYPE_UDP) < 0) {
        puts("Could not initialize channel");
        return;
    }

    if (sd_channel_write_protobuf(&channel, (ProtobufCMessage *) env) < 0) {
        puts("Could not write protobuf");
        return;
    }

    puts("Sent announce");

    envelope__free_unpacked(env, NULL);
    sd_channel_close(&channel);
}

static void handle_discover()
{
    struct sd_server server;
    struct sd_channel channel;
    DiscoverMessage *msg;
    Envelope *env;

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

        if (sd_channel_receive_protobuf(&channel,
                (ProtobufCMessageDescriptor *) &envelope__descriptor,
                (ProtobufCMessage **) &env) < 0) {
            puts("Unable to receive protobuf");
            goto out;
        }

        if (unpack_signed_protobuf(&discover_message__descriptor,
                    (ProtobufCMessage **) &msg, env, NULL) < 0) {
            puts("Received invalid signed envelope");
            goto out;
        }

        sd_log(LOG_LEVEL_DEBUG, "Received discovery message");

        announce(channel.addr, msg->port);

        discover_message__free_unpacked(msg, NULL);
        envelope__free_unpacked(env, NULL);
    }

out:
    sd_server_close(&server);
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

    if (sd_keys_from_config_file(&keys, argv[1]) < 0)
        return -1;
    if ((numservices = sd_service_from_config_file(&services, argv[1])) <= 0)
        return -1;

    announce_message__init(&announce_message);
    announce_message.version = VERSION;
    announce_message.pubkey.data = keys.pk.sign;
    announce_message.pubkey.len = sizeof(keys.pk.sign);

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
