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

#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>

#include <sodium/crypto_auth.h>
#include <sodium/crypto_box.h>
#include <sodium/utils.h>

#include "lib/cfg.h"
#include "lib/common.h"
#include "lib/log.h"
#include "lib/server.h"

#include "proto/discovery.pb-c.h"

static uint8_t pk[crypto_box_PUBLICKEYBYTES];
static uint8_t sk[crypto_box_SECRETKEYBYTES];

#define LISTEN_PORT 6667

static void announce(struct sockaddr_storage addr, uint32_t port)
{
    AnnounceEnvelope env = ANNOUNCE_ENVELOPE__INIT;
    AnnounceMessage msg = ANNOUNCE_MESSAGE__INIT;
    uint8_t msgbuf[4096];
    uint8_t mac[crypto_auth_BYTES];
    struct sd_channel channel;
    char host[128], service[16];
    size_t len;

    if (getnameinfo((struct sockaddr *) &addr, sizeof(addr),
                host, sizeof(host), NULL, 0, 0) != 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not extract address");
        return;
    }

    snprintf(service, sizeof(service), "%u", port);

    msg.version = VERSION;
    msg.port = LISTEN_PORT;
    msg.pubkey.len = crypto_box_PUBLICKEYBYTES;
    msg.pubkey.data = pk;
    len = announce_message__get_packed_size(&msg);
    if (len > sizeof(msgbuf)) {
        sd_log(LOG_LEVEL_ERROR, "Announce message longer than buffer");
        goto out;
    }
    announce_message__pack(&msg, msgbuf);

    crypto_auth(mac, msgbuf, len, pk);

    env.announce.data = msgbuf;
    env.announce.len = len;
    env.mac.data = mac;
    env.mac.len = crypto_auth_BYTES;

    if (sd_channel_init_from_host(&channel, host, service, SD_CHANNEL_TYPE_UDP) < 0) {
        puts("Could not initialize channel");
        return;
    }

    if (sd_channel_write_protobuf(&channel, (ProtobufCMessage *) &env) < 0) {
        puts("Could not write protobuf");
        return;
    }

out:
    sd_channel_close(&channel);
}

static void handle_discover()
{
    struct sd_server server;
    struct sd_channel channel;
    DiscoverEnvelope *env;
    DiscoverMessage *msg;

    if (sd_server_init(&server, NULL, "6667", SD_CHANNEL_TYPE_UDP) < 0) {
        puts("Unable to init listening channel");
        return;
    }

    while (true) {
        waitpid(-1, NULL, WNOHANG);

        if (sd_server_accept(&server, &channel) < 0) {
            puts("Unable to accept connection");
            return;
        }

        sd_log(LOG_LEVEL_DEBUG, "Received announce");

        if (sd_channel_receive_protobuf(&channel,
                (ProtobufCMessageDescriptor *) &discover_envelope__descriptor,
                (ProtobufCMessage **) &env) < 0) {
            puts("Unable to receive protobuf");
            return;
        }

        if (env->encrypted) {
            sd_log(LOG_LEVEL_ERROR, "Encrypted discover message not yet supported");
            goto out;
        }

        msg = discover_message__unpack(NULL, env->discover.len, env->discover.data);
        if (msg == NULL) {
            sd_log(LOG_LEVEL_ERROR, "Could not unpack discover message");
            goto out;
        }

        if (crypto_auth_verify(env->mac.data, env->discover.data, env->discover.len, msg->pubkey.data) != 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not verify MAC");
            goto out;
        }

        announce(channel.addr, msg->port);

        discover_message__free_unpacked(msg, NULL);
        discover_envelope__free_unpacked(env, NULL);
    }

out:
    sd_server_close(&server);
}

int main(int argc, char *argv[])
{
    struct cfg cfg;
    char *key;

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
    if (sodium_hex2bin(pk, sizeof(pk), key, strlen(key), NULL, NULL, NULL) < 0) {
        puts("Could not decode public key");
        return -1;
    }
    free(key);

    key = cfg_get_str_value(&cfg, "server", "secret_key");
    if (key == NULL) {
        puts("Could not retrieve secret key from config");
        return -1;
    }
    if (sodium_hex2bin(sk, sizeof(sk), key, strlen(key), NULL, NULL, NULL)) {
        puts("Could not decode public key");
        return -1;
    }
    free(key);

    handle_discover();

    return 0;
}
