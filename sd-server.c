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

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sodium.h>

#include "lib/common.h"
#include "lib/log.h"
#include "lib/server.h"
#include "lib/service.h"

#include "proto/connect.pb-c.h"

struct session;
static struct session {
    uint32_t sessionid;
    struct sd_symmetric_key session_key;

    struct sd_service_parameter *parameters;
    size_t nparameters;

    struct session *next;
} *sessions = NULL;

static struct sd_sign_key_public *whitelistkeys;
static uint32_t nwhitelistkeys;

static struct sd_sign_key_pair local_keys;
static struct sd_service service;

static int is_whitelisted(const struct sd_sign_key_public *key)
{
    uint32_t i;

    if (nwhitelistkeys == 0) {
        return 1;
    }

    for (i = 0; i < nwhitelistkeys; i++) {
        if (!memcmp(key->data, whitelistkeys[i].data, sizeof(key->data))) {
            return 1;
        }
    }

    return 0;
}

static int handle_query(struct sd_channel *channel)
{
    QueryResults results = QUERY_RESULTS__INIT;
    QueryResults__Parameter **parameters;
    const struct sd_service_parameter *params;
    struct sd_sign_key_public remote_key;
    int i, n;

    if (await_encryption(channel, &local_keys, &remote_key) < 0) {
        puts("Unable to negotiate encryption");
        return -1;
    }

    if (!is_whitelisted(&remote_key)) {
        puts("Received connection from unknown signature key");
        return -1;
    }

    results.name = service.name;
    results.type = service.type;
    results.subtype = service.subtype;
    results.version = (char *) service.version();
    results.location = service.location;
    results.port = service.port;

    n = service.parameters(&params);
    parameters = malloc(sizeof(QueryResults__Parameter *) * n);
    for (i = 0; i < n; i++) {
        QueryResults__Parameter *parameter = malloc(sizeof(QueryResults__Parameter));
        query_results__parameter__init(parameter);

        parameter->key = (char *) params[i].name;
        parameter->n_value = params[i].nvalues;
        parameter->value = (char **) params[i].values;

        parameters[i] = parameter;
    }
    results.parameters = parameters;
    results.n_parameters = n;

    sd_channel_write_protobuf(channel, (ProtobufCMessage *) &results);

    return 0;
}

static int convert_params(struct sd_service_parameter **out, const ConnectionRequestMessage *msg)
{
    struct sd_service_parameter *params;
    size_t i;

    *out = NULL;

    params = malloc(sizeof(struct sd_service_parameter) * msg->n_parameters);
    for (i = 0; i < msg->n_parameters; i++) {
        params[i].name = strdup(msg->parameters[i]->key);
        params[i].values = malloc(sizeof(char *));
        params[i].values[0] = strdup(msg->parameters[i]->value);
        params[i].nvalues = 1;
    }

    *out = params;

    return 0;
}

static int handle_request(struct sd_channel *channel)
{
    ConnectionRequestMessage *request;
    ConnectionTokenMessage token = CONNECTION_TOKEN_MESSAGE__INIT;
    struct sd_sign_key_public remote_sign_key;
    struct sd_symmetric_key session_key;
    struct sd_service_parameter *params;
    struct session *session;

    if (await_encryption(channel, &local_keys, &remote_sign_key) < 0) {
        puts("Unable to await encryption");
        return -1;
    }

    if (!is_whitelisted(&remote_sign_key)) {
        puts("Received connection from unknown signature key");
        return -1;
    }

    if (sd_channel_receive_protobuf(channel,
            &connection_request_message__descriptor,
            (ProtobufCMessage **) &request) < 0) {
        puts("Unable to receive request");
        return -1;
    }

    if (sd_symmetric_key_generate(&session_key) < 0) {
        puts("Unable to generate sesson session_key");
        return -1;
    }

    token.token.data = session_key.data;
    token.token.len = sizeof(session_key.data);
    token.sessionid = randombytes_random();

    if (sd_channel_write_protobuf(channel, &token.base) < 0) {
        puts("Unable to send connection token");
        return -1;
    }

    if (convert_params(&params, request) < 0) {
        puts("Unable to convert parameters");
        return -1;
    }
    connection_request_message__free_unpacked(request, NULL);

    session = malloc(sizeof(struct session));
    session->sessionid = token.sessionid;
    session->parameters = params;
    session->nparameters = request->n_parameters;
    memcpy(session->session_key.data, session_key.data, sizeof(session_key));
    session->next = sessions;
    sessions = session;

    return 0;
}

static int handle_connect(struct sd_channel *channel)
{
    ConnectionInitiation *initiation;
    struct session *session, *prev = NULL;

    if (sd_channel_receive_protobuf(channel,
                &connection_initiation__descriptor,
                (ProtobufCMessage **) &initiation) < 0) {
        puts("Could not receive connection initiation");
        return -1;
    }

    for (session = sessions; session; session = session->next) {
        if (session->sessionid == initiation->sessionid)
            break;
        prev = session;
    }
    connection_initiation__free_unpacked(initiation, NULL);

    if (session == NULL) {
        puts("Could not find session for client");
        return -1;
    }

    if (prev == NULL)
        sessions = session->next;
    else
        prev->next = session->next;

    if (sd_channel_enable_encryption(channel, &session->session_key, 1) < 0) {
        puts("Could not enable symmetric encryption");
        return -1;
    }

    if (service.handle(channel, session->parameters, session->nparameters) < 0) {
        puts("Service could not handle connection");
        return -1;
    }

    sd_service_parameters_free(session->parameters, session->nparameters);
    free(session);

    return 0;
}

static int read_whitelist(struct sd_sign_key_public **out, const char *file)
{
    struct sd_sign_key_public *keys = NULL;
    FILE *stream = NULL;
    char *line = NULL;
    size_t nkeys = 0, length;
    ssize_t read;

    *out = NULL;

    stream = fopen(file, "r");
    if (stream == NULL)
        return -1;

    while ((read = getline(&line, &length, stream)) != -1) {
        if (line[read - 1] == '\n')
            line[read - 1] = '\0';

        keys = realloc(keys, sizeof(struct sd_sign_key_public) * ++nkeys);
        if (sd_sign_key_public_from_hex(&keys[nkeys - 1], line) < 0) {
            printf("Invalid key '%s'\n", line);
            return -1;
        }
    }
    free(line);

    if (!feof(stream)) {
        fclose(stream);
        free(keys);
        return -1;
    }

    fclose(stream);
    *out = keys;

    return nkeys;
}

static void
sigchild_handler(int sig)
{
    int status;
    UNUSED(sig);
    while (waitpid(-1, &status, WNOHANG) > 0);
}

static int setup_signals(void)
{
    struct sigaction sigchld_action;

    sigemptyset(&sigchld_action.sa_mask);
    sigchld_action.sa_flags = 0;
    sigchld_action.sa_handler = sigchild_handler;

    sigaction(SIGCHLD, &sigchld_action, NULL);

    return 0;
}

int main(int argc, char *argv[])
{
    const char *config, *servicename;
    struct sd_server server;
    struct sd_channel channel;
    int ret;

    if (argc < 3 || argc > 4) {
        printf("USAGE: %s <CONFIG> <SERVICENAME> [<CLIENT_WHITELIST>]\n", argv[0]);
        return -1;
    }

    config = argv[1];
    servicename = argv[2];

    if (argc == 4) {
        ret = read_whitelist(&whitelistkeys, argv[3]);
        if (ret < 0) {
            puts("Could not read client whitelist");
            return -1;
        }
        nwhitelistkeys = ret;

        printf("Read %d keys from whitelist\n", nwhitelistkeys);
    }

    if (setup_signals() < 0) {
        puts("Could not set up signal handlers");
        return -1;
    }

    if (sodium_init() < 0) {
        puts("Could not init libsodium");
        return -1;
    }

    if (sd_service_from_config_file(&service, servicename, config) < 0) {
        puts("Could not parse services");
        return -1;
    }

    if (sd_sign_key_pair_from_config_file(&local_keys, config) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (sd_server_init(&server, NULL, service.port, SD_CHANNEL_TYPE_TCP) < 0) {
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
            case CONNECTION_TYPE__TYPE__QUERY:
                sd_log(LOG_LEVEL_DEBUG, "Received query");
                handle_query(&channel);
                break;
            case CONNECTION_TYPE__TYPE__REQUEST:
                sd_log(LOG_LEVEL_DEBUG, "Received request");
                handle_request(&channel);
                break;
            case CONNECTION_TYPE__TYPE__CONNECT:
                sd_log(LOG_LEVEL_DEBUG, "Received connect");
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
