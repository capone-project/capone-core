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
#include <string.h>
#include <stdio.h>
#include <sodium.h>
#include <inttypes.h>

#include "lib/common.h"
#include "lib/channel.h"

#include "proto/connect.pb-c.h"

struct params {
    const char *key;
    const char *value;
};

static struct sd_key_pair keys;
static struct sd_key_public remote_keys;

static void usage(const char *prog)
{
    printf("USAGE: %s (request|connect)\n"
            "\trequest <CONFIG> <KEY> <HOST> <PORT> [<PARAMETER>...]\n"
            "\tconnect <SESSIONID> <TOKEN> <HOST> <PORT> <TYPE>\n", prog);
    exit(-1);
}

static int request_connection(struct sd_channel *channel,
        const struct params *params, int nparams)
{
    ConnectionType type = CONNECTION_TYPE__INIT;
    ConnectionRequestMessage request = CONNECTION_REQUEST_MESSAGE__INIT;
    ConnectionTokenMessage *token;
    char tokenhex[crypto_secretbox_KEYBYTES * 2 + 1];
    int i;

    type.type = CONNECTION_TYPE__TYPE__REQUEST;
    sd_channel_write_protobuf(channel, &type.base);

    if (initiate_encryption(channel, &keys, &remote_keys) < 0) {
        puts("Unable to initiate encryption");
        return -1;
    }

    if (nparams) {
        ConnectionRequestMessage__Parameter **parameters =
            malloc(sizeof(ConnectionRequestMessage__Parameter *) * nparams);

        for (i = 0; i < nparams; i++) {
            ConnectionRequestMessage__Parameter *param =
                malloc(sizeof(ConnectionRequestMessage__Parameter));
            connection_request_message__parameter__init(param);

            param->key = (char *) params[i].key;
            param->value = (char *) params[i].value;

            parameters[i] = param;
        }

        request.parameters = parameters;
        request.n_parameters = nparams;
    } else {
        request.parameters = NULL;
        request.n_parameters = 0;
    }

    if (sd_channel_write_protobuf(channel, &request.base) < 0) {
        puts("Unable to send connection request");
        return -1;
    }

    if (sd_channel_receive_protobuf(channel,
            &connection_token_message__descriptor,
            (ProtobufCMessage **) &token) < 0) {
        puts("Unable to receive token");
        return -1;
    }
    assert(token->token.len == crypto_secretbox_KEYBYTES);

    sodium_bin2hex(tokenhex, sizeof(tokenhex),
            token->token.data, token->token.len);
    printf("token:     %s\n"
           "sessionid: %"PRIu32"\n", tokenhex, token->sessionid);

    return 0;
}

static int parse_params(struct params **out, int argc, char *argv[])
{
    struct params *params;
    int i;

    params = malloc(sizeof(struct params) * argc);

    for (i = 0; i < argc; i++) {
        char *line = argv[i], *key, *value;

        if ((key = strtok(line, "=")) == NULL)
            return -1;
        if ((value = strtok(NULL, "=")) == NULL)
            return -1;

        params[i].key = key;
        params[i].value = value;
    }

    *out = params;

    return i;
}

static int cmd_request(int argc, char *argv[])
{
    const char *config, *key, *host, *port;
    struct sd_channel channel;
    struct params *params;
    int nparams;

    if (argc < 6) {
        usage(argv[0]);
    }

    config = argv[2];
    key = argv[3];
    host = argv[4];
    port = argv[5];

    if ((nparams = parse_params(&params, argc - 6, argv + 6)) < 0) {
        puts("Could not parse parameters");
        return -1;
    }

    if (sd_key_pair_from_config_file(&keys, config) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (sd_key_public_from_hex(&remote_keys, key) < 0) {
        puts("Could not parse remote public key");
        return -1;
    }

    if (sd_channel_init_from_host(&channel, host, port, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Could not initialize channel");
        return -1;
    }

    if (sd_channel_connect(&channel) < 0) {
        puts("Could not connect to server");
        return -1;
    }

    if (request_connection(&channel, params, nparams) < 0)
        return -1;

    sd_channel_close(&channel);

    return 0;
}

static int cmd_connect(int argc, char *argv[])
{
    ConnectionType conntype = CONNECTION_TYPE__INIT;
    ConnectionInitiation initiation = CONNECTION_INITIATION__INIT;
    const char *token, *host, *port, *type;
    struct sd_channel channel;
    uint32_t sessionid;
    int saved_errno;

    if (argc != 7)
        usage(argv[0]);

    token = argv[3];
    host = argv[4];
    port = argv[5];
    type = argv[6];

    saved_errno = errno;
    sessionid = strtol(argv[2], NULL, 10);
    if (errno != 0) {
        printf("Invalid session ID %s\n", argv[2]);
        return -1;
    }
    errno = saved_errno;

    if (sd_channel_init_from_host(&channel, host, port, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Could not initialize channel");
        return -1;
    }

    if (sd_channel_connect(&channel) < 0) {
        puts("Could not connect to server");
        return -1;
    }

    conntype.type = CONNECTION_TYPE__TYPE__CONNECT;
    if (sd_channel_write_protobuf(&channel, &conntype.base) < 0) {
        puts("Could not send connection type");
        return -1;
    }

    initiation.sessionid = sessionid;
    if (sd_channel_write_protobuf(&channel, &initiation.base) < 0 ){
        puts("Could not initiate session");
        return -1;
    }

    /* TODO: enable symmetric encryption */
    UNUSED(token);

    /* TODO: start service */
    UNUSED(type);

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        usage(argv[0]);

    if (sodium_init() < 0) {
        puts("Could not init libsodium");
        return -1;
    }

    if (!strcmp(argv[1], "request"))
        return cmd_request(argc, argv);
    else if (!strcmp(argv[1], "connect"))
        return cmd_connect(argc, argv);

    usage(argv[0]);
}
