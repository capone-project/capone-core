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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "lib/cfg.h"
#include "lib/common.h"
#include "lib/log.h"
#include "lib/server.h"

#include "proto/discovery.pb-c.h"

#define LISTEN_PORT 6668

static uint8_t rpk[crypto_box_PUBLICKEYBYTES];
static struct sd_keys keys;

static void probe(void *payload)
{
    DiscoverMessage msg = DISCOVER_MESSAGE__INIT;
    Envelope *env;
    struct sd_channel channel;

    UNUSED(payload);

    msg.version = VERSION;
    msg.port = LISTEN_PORT;
    msg.pubkey.data = keys.sign_pk;
    msg.pubkey.len = sizeof(keys.sign_pk);

    if (pack_signed_protobuf(&env, (ProtobufCMessage *) &msg, keys.sign_pk, keys.sign_sk) < 0) {
        puts("Unable to sign protobuf");
        goto out;
    }

    if (sd_channel_init_from_host(&channel, "224.0.0.1", "6667", SD_CHANNEL_TYPE_UDP) < 0) {
        puts("Unable to initialize channel");
        goto out;
    }

    while (true) {
        if (sd_channel_write_protobuf(&channel, (ProtobufCMessage *) env) < 0) {
            puts("Unable to write protobuf");
            goto out;
        }

        sd_log(LOG_LEVEL_DEBUG, "Sent probe message");

        sleep(5);
    }

out:
    sd_channel_close(&channel);
}

#include <netinet/in.h>
#include <arpa/inet.h>

static void handle_announce()
{
    struct sd_server server;
    struct sd_channel channel;
    AnnounceMessage *msg = NULL;
    Envelope *env = NULL;

    if (sd_server_init(&server, NULL, "6668", SD_CHANNEL_TYPE_UDP) < 0) {
        puts("Unable to init listening channel");
        goto out;
    }

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

    if (unpack_signed_protobuf(&announce_message__descriptor,
                (ProtobufCMessage **) &msg, env) < 0) {
        puts("Unable to unpack signed protobuf");
        goto out;
    }

    memcpy(rpk, msg->pubkey.data, sizeof(rpk));

    sd_log(LOG_LEVEL_DEBUG, "Successfully retrieved remote public key from server (version %s)",
            msg->version);

out:
    announce_message__free_unpacked(msg, NULL);
    envelope__free_unpacked(env, NULL);
    sd_channel_close(&channel);
}

int main(int argc, char *argv[])
{
    int pid;

    if (sodium_init() < 0) {
        return -1;
    }

    if (argc != 2) {
        printf("USAGE: %s <CONFIG>\n", argv[0]);
        return -1;
    }

    if (sd_keys_from_config_file(&keys, argv[1]) < 0) {
        puts("Could not parse config");
        return -1;
    }

    pid = spawn(probe, NULL);
    handle_announce();

    kill(pid, SIGTERM);
    waitpid(-1, NULL, 0);

    return 0;
}
