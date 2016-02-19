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
#include <stdio.h>
#include <sodium.h>

#include "lib/common.h"
#include "lib/channel.h"

#include "proto/connect.pb-c.h"

struct params {
    const char *key;
    const char *value;
};

static struct sd_keys keys;
static struct sd_keys_public remote_keys;

static int request_connection(struct sd_channel *channel,
        const struct params *params, int nparams)
{
    ConnectionRequestMessage request = CONNECTION_REQUEST_MESSAGE__INIT;
    ConnectionRequestMessage__Parameter **parameters;
    ConnectionTokenMessage *token;
    char tokenhex[crypto_secretbox_KEYBYTES * 2 + 1];
    int i;

    if (initiate_encryption(channel, &keys, &remote_keys) < 0) {
        puts("Unable to initiate encryption");
        return -1;
    }

    parameters = malloc(sizeof(ConnectionRequestMessage__Parameter *) * nparams);
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
    printf("Received token %s\n", tokenhex);

    return 0;
}

static int start_connection(void)
{
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

int main(int argc, char *argv[])
{
    const char *config, *key, *host, *port;
    struct sd_channel channel;
    struct params *params;
    int nparams;

    if (argc < 5) {
        printf("USAGE: %s <CONFIG> <KEY> <HOST> <PORT> [<PARAMETER>...]\n", argv[0]);
        return -1;
    }

    config = argv[1];
    key = argv[2];
    host = argv[3];
    port = argv[4];

    if ((nparams = parse_params(&params, argc - 5, argv + 5)) < 0) {
        puts("Could not parse parameters");
        return -1;
    }

    if (sodium_init() < 0) {
        puts("Could not init libsodium");
        return -1;
    }

    if (sd_keys_from_config_file(&keys, config) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (sd_keys_public_from_hex(&remote_keys, key) < 0) {
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

    if (start_connection() < 0)
        return -1;

    sd_channel_close(&channel);

    return 0;
}
