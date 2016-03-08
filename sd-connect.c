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

#include "lib/channel.h"
#include "lib/proto.h"
#include "lib/service.h"

static struct sd_sign_key_pair local_keys;
static struct sd_sign_key_public remote_key;

static void usage(const char *prog)
{
    printf("USAGE: %s (request|connect)\n"
            "\tquery <CONFIG> <KEY> <HOST> <PORT>\n"
            "\trequest <CONFIG> <KEY> <HOST> <PORT> [<PARAMETER>...]\n"
            "\tconnect <SESSIONID> <TOKEN> <HOST> <PORT> <SERVICE>\n", prog);
    exit(-1);
}

static int parse_params(struct sd_service_parameter **out, int argc, char *argv[])
{
    struct sd_service_parameter *params;
    int i;

    params = malloc(sizeof(struct sd_service_parameter) * argc);

    for (i = 0; i < argc; i++) {
        char *line = argv[i], *key, *value;

        if ((key = strtok(line, "=")) == NULL)
            return -1;
        if ((value = strtok(NULL, "=")) == NULL)
            return -1;

        params[i].key = key;
        params[i].values = malloc(sizeof(char *));
        params[i].values[0] = value;
        params[i].nvalues = 1;
    }

    *out = params;

    return i;
}

static int cmd_query(int argc, char *argv[])
{
    struct sd_channel channel;
    char *config, *key, *host, *port;

    if (argc != 6)
        usage(argv[0]);

    config = argv[2];
    key = argv[3];
    host = argv[4];
    port = argv[5];

    if (sd_sign_key_pair_from_config_file(&local_keys, config) < 0) {
        puts("Could not parse sign keys");
        return -1;
    }

    if (sd_sign_key_public_from_hex(&remote_key, key) < 0) {
        puts("Could not parse remote public key");
        return -1;
    }

    if (sd_proto_initiate_connection_type(&channel, host, port, SD_CONNECTION_TYPE_QUERY) < 0) {
        puts("Could not establish connection");
        return -1;
    }

    if (sd_proto_initiate_encryption(&channel, &local_keys, &remote_key) < 0) {
        puts("Unable to initiate encryption");
        return -1;
    }

    if (sd_proto_send_query(&channel, &remote_key) < 0)
        return -1;

    sd_channel_close(&channel);

    return 0;
}

static int cmd_request(int argc, char *argv[])
{
    char sessionkey_hex[crypto_secretbox_KEYBYTES * 2 + 1];
    const char *config, *key, *host, *port;
    struct sd_service_parameter *params;
    struct sd_service_session session;
    struct sd_channel channel;
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

    if (sd_sign_key_pair_from_config_file(&local_keys, config) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (sd_sign_key_public_from_hex(&remote_key, key) < 0) {
        puts("Could not parse remote public key");
        return -1;
    }

    if (sd_proto_initiate_connection_type(&channel, host, port, SD_CONNECTION_TYPE_REQUEST) < 0) {
        puts("Could not establish connection");
        return -1;
    }

    if (sd_proto_initiate_encryption(&channel, &local_keys, &remote_key) < 0) {
        puts("Unable to initiate encryption");
        return -1;
    }

    if (sd_proto_send_request(&session, &channel, params, nparams) < 0) {
        puts("Unable to request session");
        return -1;
    }

    sodium_bin2hex(sessionkey_hex, sizeof(sessionkey_hex),
            session.session_key.data, sizeof(session.session_key.data));
    printf("sessionkey: %s\n"
           "sessionid:  %"PRIu32"\n", sessionkey_hex, session.sessionid);

    sd_channel_close(&channel);

    return 0;
}

static int cmd_connect(int argc, char *argv[])
{
    struct sd_service service;
    const char *token, *host, *port;
    struct sd_channel channel;
    uint32_t sessionid;
    int saved_errno;

    if (argc < 7)
        usage(argv[0]);

    token = argv[3];
    host = argv[4];
    port = argv[5];

    if (sd_service_from_type(&service, argv[6]) < 0) {
        printf("Invalid service %s\n", argv[6]);
        return -1;
    }

    saved_errno = errno;
    sessionid = strtol(argv[2], NULL, 10);
    if (errno != 0) {
        printf("Invalid session ID %s\n", argv[2]);
        return -1;
    }
    errno = saved_errno;

    if (sd_proto_initiate_connection_type(&channel, host, port, SD_CONNECTION_TYPE_CONNECT) < 0) {
        puts("Could not start connection");
        return -1;
    }

    if (sd_proto_initiate_session(&channel, token, sessionid) < 0) {
        puts("Could not connect to session");
        return -1;
    }

    if (service.invoke(&channel, argc - 7, argv + 7) < 0) {
        puts("Could not invoke service");
        return -1;
    }

    sd_channel_close(&channel);

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

    if (!strcmp(argv[1], "query"))
        return cmd_query(argc, argv);
    if (!strcmp(argv[1], "request"))
        return cmd_request(argc, argv);
    else if (!strcmp(argv[1], "connect"))
        return cmd_connect(argc, argv);

    usage(argv[0]);
}
