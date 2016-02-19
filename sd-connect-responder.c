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

#include <sodium.h>

#include "lib/common.h"
#include "lib/server.h"
#include "lib/service.h"

#include "proto/connect.pb-c.h"

static struct sd_keys keys;
static struct sd_service service;

static int handle_connect(struct sd_channel *channel)
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

    if (sd_channel_write_protobuf(channel, &token.base) < 0) {
        puts("Unable to send connection token");
        return -1;
    }

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

    if (sd_keys_from_config_file(&keys, config) < 0) {
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
        if (sd_server_accept(&server, &channel) < 0) {
            puts("Could not accept connection");
            return -1;
        }

        handle_connect(&channel);
        sd_channel_close(&channel);
    }

    sd_server_close(&server);


    return 0;
}
