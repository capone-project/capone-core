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

#include "lib/common.h"
#include "lib/cfg.h"
#include "lib/log.h"
#include "lib/proto.h"
#include "lib/server.h"

#include "proto/discovery.pb-c.h"

#define LISTEN_PORT 6668

static struct sd_sign_key_pair local_keys;

static int send_discover(struct sd_channel *channel)
{
    DiscoverMessage msg = DISCOVER_MESSAGE__INIT;

    msg.version = VERSION;
    msg.port = LISTEN_PORT;

    if (sd_channel_write_protobuf(channel, &msg.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send discover: %s",
                strerror(errno));
        return -1;
    }

    return 0;
}

static void *probe(void *payload)
{
    struct sd_channel channel;

    UNUSED(payload);

    if (sd_channel_init_from_host(&channel, "224.0.0.1", "6667", SD_CHANNEL_TYPE_UDP) < 0) {
        puts("Unable to initialize channel");
        goto out;
    }

    while (true) {
        if (send_discover(&channel) < 0) {
            puts("Unable to write protobuf");
            goto out;
        }

        sd_log(LOG_LEVEL_DEBUG, "Sent probe message");

        sleep(5);
    }

out:
    sd_channel_close(&channel);

    return NULL;
}

static void handle_announce(struct sd_channel *channel)
{
    struct sd_sign_key_hex remote_key;
    AnnounceMessage *announce = NULL;
    unsigned i;

    while (true) {
        if (sd_channel_receive_protobuf(channel,
                    (ProtobufCMessageDescriptor *) &announce_message__descriptor,
                    (ProtobufCMessage **) &announce) < 0) {
            puts("Unable to receive protobuf");
            goto out;
        }

        if (sd_sign_key_hex_from_bin(&remote_key,
                    announce->sign_key.data, announce->sign_key.len) < 0)
        {
            puts("Unable to retrieve remote sign key");
            goto out;
        }

        printf("%s (v%s)\n", remote_key.data, announce->version);

        for (i = 0; i < announce->n_services; i++) {
            AnnounceMessage__Service *service = announce->services[i];

            printf("\t%s -> %s (%s)\n", service->port, service->name, service->category);
        }

        announce_message__free_unpacked(announce, NULL);
    }

out:
    if (announce)
        announce_message__free_unpacked(announce, NULL);
}

static void undirected_discovery()
{
    struct sd_server server;
    struct sd_channel channel;
    struct sd_thread t;

    channel.fd = -1;

    sd_spawn(&t, probe, NULL);

    if (sd_server_init(&server, NULL, "6668", SD_CHANNEL_TYPE_UDP) < 0) {
        puts("Unable to init listening channel");
        goto out;
    }

    if (sd_server_enable_broadcast(&server) < 0) {
        puts("Unable to enable broadcasting");
        goto out;
    }

    if (sd_server_accept(&server, &channel) < 0) {
        puts("Unable to accept connection");
        goto out;
    }

    handle_announce(&channel);

out:
    sd_channel_close(&channel);
    sd_kill(&t);
}

static void directed_discovery(const struct sd_sign_key_public *remote_key,
        const char *host, const char *port)
{
    struct sd_channel channel;

    if (sd_channel_init_from_host(&channel, host, port, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Unable to initiate channel");
        goto out;
    }

    if (sd_channel_connect(&channel) < 0) {
        puts("Unable to connect");
        goto out;
    }

    if (sd_proto_initiate_encryption(&channel, &local_keys, remote_key) < 0) {
        puts("Unable to initiate encryption");
        goto out;
    }

    if (send_discover(&channel) < 0) {
        puts("Unable to send directed discover");
        goto out;
    }

    handle_announce(&channel);

out:
    sd_channel_close(&channel);
}

int main(int argc, char *argv[])
{
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts("sd-discover " VERSION "\n"
             "Copyright (C) 2016 Patrick Steinhardt\n"
             "License GPLv3: GNU GPL version 3 <http://gnu.org/licenses/gpl.html>.\n"
             "This is free software; you are free to change and redistribute it.\n"
             "There is NO WARRANTY, to the extent permitted by the law.");
        return 0;
    }

    if (argc != 2 && argc != 5) {
        printf("USAGE: %s <CONFIG> [<KEY> <HOST> <PORT>]\n", argv[0]);
        return -1;
    }

    if (sodium_init() < 0) {
        return -1;
    }

    if (sd_sign_key_pair_from_config_file(&local_keys, argv[1]) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (argc == 2) {
        undirected_discovery();
    } else if (argc == 5) {
        struct sd_sign_key_public remote_key;

        if (sd_sign_key_public_from_hex(&remote_key, argv[2]) < 0) {
            return -1;
        }

        directed_discovery(&remote_key, argv[3], argv[4]);
    }

    return 0;
}
