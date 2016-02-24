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
#include <sodium.h>

#include "lib/common.h"
#include "lib/server.h"
#include "lib/service.h"

#include "proto/connect.pb-c.h"

static struct session {
    uint32_t sessionid;
    uint8_t token[crypto_secretbox_KEYBYTES];
} *sessions = NULL;
static uint32_t nsessions = 0;

static struct sd_key_pair keys;
static struct sd_service service;

static int handle_request(struct sd_channel *channel)
{
    ConnectionRequestMessage *request;
    ConnectionTokenMessage token = CONNECTION_TOKEN_MESSAGE__INIT;
    uint8_t key[crypto_secretbox_KEYBYTES];

    if (await_encryption(channel, &keys) < 0) {
        puts("Unable to await encryption");
        return -1;
    }

    if (sd_channel_receive_protobuf(channel,
            &connection_request_message__descriptor,
            (ProtobufCMessage **) &request) < 0) {
        puts("Unable to receive request");
        return -1;
    }

    randombytes_buf(key, sizeof(key));
    token.token.data = key;
    token.token.len = sizeof(key);
    token.sessionid = randombytes_random();

    if (sd_channel_write_protobuf(channel, &token.base) < 0) {
        puts("Unable to send connection token");
        return -1;
    }

    nsessions += 1;
    sessions = realloc(sessions, nsessions * sizeof(struct session));
    sessions[nsessions - 1].sessionid = token.sessionid;
    memcpy(sessions[nsessions - 1].token, key, sizeof(key));

    return 0;
}

static int handle_connect(struct sd_channel *channel)
{
    ConnectionInitiation *initiation;
    uint8_t *token = NULL;
    uint32_t i;

    if (sd_channel_receive_protobuf(channel,
                &connection_initiation__descriptor,
                (ProtobufCMessage **) &initiation) < 0) {
        puts("Could not receive connection initiation");
        return -1;
    }

    for (i = 0; i < nsessions; i++) {
        if (sessions[i].sessionid == initiation->sessionid) {
            token = sessions[i].token;
            break;
        }
    }

    if (token == NULL) {
        puts("Could not find session for client");
        return -1;
    }

    printf("Client %u connected\n", sessions[i].sessionid);

    return 0;
}

int main(int argc, char *argv[])
{
    const char *config, *servicename;
    struct sd_server server;
    struct sd_channel channel;

    if (argc != 3) {
        printf("USAGE: %s <CONFIG> <SERVICENAME>\n", argv[0]);
        return -1;
    }

    config = argv[1];
    servicename = argv[2];

    if (sodium_init() < 0) {
        puts("Could not init libsodium");
        return -1;
    }

    if (sd_service_from_config_file(&service, servicename, config) < 0) {
        puts("Could not parse services");
        return -1;
    }

    if (sd_key_pair_from_config_file(&keys, config) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (sd_server_init(&server, NULL, service.connectport, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Could not set up server");
        return -1;
    }

    if (sd_server_listen(&server) < 0) {
        puts("Could not start listening");
        return -1;
    }

    while (1) {
        ConnectionType *type;

        if (sd_server_accept(&server, &channel) < 0) {
            puts("Could not accept connection");
            return -1;
        }

        if (sd_channel_receive_protobuf(&channel,
                    (ProtobufCMessageDescriptor *) &connection_type__descriptor,
                    (ProtobufCMessage **) &type) < 0) {
            puts("Failed receiving connection type");
            return -1;
        }

        switch (type->type) {
            case CONNECTION_TYPE__TYPE__REQUEST:
                handle_request(&channel);
                break;
            case CONNECTION_TYPE__TYPE__CONNECT:
                handle_connect(&channel);
                break;
            case _CONNECTION_TYPE__TYPE_IS_INT_SIZE:
            default:
                printf("Unknown connection envelope type %d\n", type->type);
                break;
        }

        sd_channel_close(&channel);
        connection_type__free_unpacked(type, NULL);
    }

    sd_server_close(&server);

    return 0;
}
