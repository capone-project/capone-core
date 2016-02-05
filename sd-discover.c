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

#include <sodium/crypto_box.h>
#include <sodium/crypto_auth.h>
#include <sodium/utils.h>

#include "lib/cfg.h"
#include "lib/common.h"
#include "lib/log.h"
#include "lib/server.h"

#include "proto/discovery.pb-c.h"

#define LISTEN_PORT 6668

static uint8_t pk[crypto_box_PUBLICKEYBYTES];
static uint8_t sk[crypto_box_SECRETKEYBYTES];

static uint8_t rpk[crypto_box_PUBLICKEYBYTES];

static void probe(void *payload)
{
    struct sd_channel channel;
    DiscoverEnvelope env = DISCOVER_ENVELOPE__INIT;
    DiscoverMessage msg = DISCOVER_MESSAGE__INIT;
    uint8_t msgbuf[4096], mac[crypto_auth_BYTES];
    size_t len;

    UNUSED(payload);

    msg.version = VERSION;
    msg.port = LISTEN_PORT;
    msg.pubkey.len = crypto_box_PUBLICKEYBYTES;
    msg.pubkey.data = pk;
    len = discover_message__get_packed_size(&msg);
    if (len > sizeof(msgbuf)) {
        sd_log(LOG_LEVEL_ERROR, "Discover message longer than buffer");
        goto out;
    }
    discover_message__pack(&msg, msgbuf);

    if (crypto_auth(mac, msgbuf, len, pk) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to sign message");
        goto out;
    }

    env.encrypted = false;
    env.mac.len = crypto_auth_BYTES;
    env.mac.data = mac;
    env.discover.data = msgbuf;
    env.discover.len = len;

    if (sd_channel_init_from_host(&channel, "224.0.0.1", "6667", SD_CHANNEL_TYPE_UDP) < 0)
        return;

    while (true) {
        if (sd_channel_write_protobuf(&channel, (struct ProtobufCMessage *) &env) < 0) {
            puts("Unable to write protobuf");
            return;
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
    AnnounceEnvelope *env = NULL;
    AnnounceMessage *msg = NULL;

    if (sd_server_init(&server, NULL, "6668", SD_CHANNEL_TYPE_UDP) < 0) {
        puts("Unable to init listening channel");
        return;
    }

    if (sd_server_accept(&server, &channel) < 0) {
        puts("Unable to accept connection");
        return;
    }

    if (sd_channel_receive_protobuf(&channel,
                (ProtobufCMessageDescriptor *) &announce_envelope__descriptor,
                (ProtobufCMessage **) &env) < 0) {
        puts("Unable to receive protobuf");
        return;
    }

    msg = announce_message__unpack(NULL, env->announce.len, env->announce.data);
    if (msg == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Could not unpack announce message");
        goto out;
    }

    if (msg->pubkey.len != sizeof(rpk)) {
        sd_log(LOG_LEVEL_ERROR, "Unexpected key size in announcement");
        goto out;
    }

    if (crypto_auth_verify(env->mac.data, env->announce.data, env->announce.len, msg->pubkey.data) != 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not verify MAC");
        goto out;
    }

    memcpy(rpk, msg->pubkey.data, sizeof(rpk));

    sd_log(LOG_LEVEL_DEBUG, "Successfully retrieved remote public key from server (version %s)",
            msg->version);

out:
    announce_message__free_unpacked(msg, NULL);
    announce_envelope__free_unpacked(env, NULL);
    sd_channel_close(&channel);
}

int main(int argc, char *argv[])
{
    int pid;
    struct cfg cfg;
    char *key;

    if (argc != 2) {
        printf("USAGE: %s <CONFIG>\n", argv[0]);
        return -1;
    }

    if (cfg_parse(&cfg, argv[1]) < 0) {
        puts("Could not parse config");
        return -1;
    }

    key = cfg_get_str_value(&cfg, "client", "public_key");
    if (key == NULL) {
        puts("Could not retrieve public key from config");
        return -1;
    }
    if (sodium_hex2bin(pk, sizeof(pk), key, strlen(key), NULL, NULL, NULL) < 0) {
        puts("Could not decode public key");
        return -1;
    }
    free(key);

    key = cfg_get_str_value(&cfg, "client", "secret_key");
    if (key == NULL) {
        puts("Could not retrieve secret key from config");
        return -1;
    }
    if (sodium_hex2bin(sk, sizeof(sk), key, strlen(key), NULL, NULL, NULL)) {
        puts("Could not decode public key");
        return -1;
    }
    free(key);

    pid = spawn(probe, NULL);
    handle_announce();

    kill(pid, SIGTERM);
    waitpid(-1, NULL, 0);

    return 0;
}
