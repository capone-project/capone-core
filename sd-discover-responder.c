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

#include "lib/cfg.h"
#include "lib/common.h"
#include "lib/log.h"
#include "lib/server.h"

#include "proto/discovery.pb-c.h"

static uint8_t sign_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
static uint8_t sign_sk[crypto_sign_ed25519_SECRETKEYBYTES];

#define LISTEN_PORT 6667

static void announce(struct sockaddr_storage addr, uint32_t port)
{
    AnnounceMessage msg = ANNOUNCE_MESSAGE__INIT;
    Envelope *env = NULL;
    struct sd_channel channel;
    char host[128], service[16];

    if (getnameinfo((struct sockaddr *) &addr, sizeof(addr),
                host, sizeof(host), NULL, 0, 0) != 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not extract address");
        return;
    }
    snprintf(service, sizeof(service), "%u", port);

    msg.version = VERSION;
    msg.port = LISTEN_PORT;
    msg.pubkey.data = sign_pk;
    msg.pubkey.len = sizeof(sign_pk);

    if (pack_signed_protobuf(&env, (ProtobufCMessage *) &msg, sign_pk, sign_sk) < 0) {
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

        sd_log(LOG_LEVEL_DEBUG, "Received announce");

        if (sd_channel_receive_protobuf(&channel,
                (ProtobufCMessageDescriptor *) &envelope__descriptor,
                (ProtobufCMessage **) &env) < 0) {
            puts("Unable to receive protobuf");
            goto out;
        }

        if (unpack_signed_protobuf(&discover_message__descriptor,
                    (ProtobufCMessage **) &msg, env) < 0) {
            puts("Received invalid signed envelope");
            goto out;
        }

        announce(channel.addr, msg->port);

        discover_message__free_unpacked(msg, NULL);
        envelope__free_unpacked(env, NULL);
    }

out:
    sd_server_close(&server);
}

int main(int argc, char *argv[])
{
    struct cfg cfg;
    char *key;

    if (sodium_init() < 0) {
        return -1;
    }

    if (argc < 3) {
        printf("USAGE: %s <SERVER_CONFIG> <SERVICE_CONFIG>..\n", argv[0]);
        return 0;
    }

    if (cfg_parse(&cfg, argv[1]) < 0) {
        puts("Could not parse config");
        return -1;
    }

    key = cfg_get_str_value(&cfg, "server", "public_key");
    if (key == NULL) {
        puts("Could not retrieve public key from config");
        return -1;
    }
    if (sodium_hex2bin(sign_pk, sizeof(sign_pk), key, strlen(key), NULL, NULL, NULL) < 0) {
        puts("Could not decode public key");
        return -1;
    }
    free(key);

    key = cfg_get_str_value(&cfg, "server", "secret_key");
    if (key == NULL) {
        puts("Could not retrieve secret key from config");
        return -1;
    }
    if (sodium_hex2bin(sign_sk, sizeof(sign_sk), key, strlen(key), NULL, NULL, NULL)) {
        puts("Could not decode public key");
        return -1;
    }
    free(key);

    handle_discover();

    return 0;
}
