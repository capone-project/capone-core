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

#include "lib/common.h"
#include "lib/channel.h"
#include "lib/log.h"

#include "proto/connect.pb-c.h"

#include "proto.h"

struct service_args {
    struct cfg *cfg;
    struct sd_service *service;
    struct sd_channel *channel;
    struct sd_service_session *session;
};

static int is_whitelisted(const struct sd_sign_key_public *key,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist);
static int convert_params(struct sd_service_parameter **out,
        const SessionRequestMessage *msg);
static void handle_service(void *payload);

int sd_proto_initiate_connection(struct sd_channel *channel,
        const char *host,
        const char *port,
        const struct sd_sign_key_pair *local_keys,
        const struct sd_sign_key_public *remote_key,
        enum sd_connection_type type)
{
    ConnectionInitiationMessage conntype = CONNECTION_INITIATION_MESSAGE__INIT;

    if (sd_channel_init_from_host(channel, host, port, SD_CHANNEL_TYPE_TCP) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not initialize channel");
        return -1;
    }

    if (sd_channel_connect(channel) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not connect to server");
        return -1;
    }

    if (sd_proto_initiate_encryption(channel, local_keys, remote_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to initiate encryption");
        return -1;
    }

    switch (type) {
        case SD_CONNECTION_TYPE_CONNECT:
            conntype.type = CONNECTION_INITIATION_MESSAGE__TYPE__CONNECT;
            break;
        case SD_CONNECTION_TYPE_REQUEST:
            conntype.type = CONNECTION_INITIATION_MESSAGE__TYPE__REQUEST;
            break;
        case SD_CONNECTION_TYPE_QUERY:
            conntype.type = CONNECTION_INITIATION_MESSAGE__TYPE__QUERY;
            break;
        default:
            sd_log(LOG_LEVEL_ERROR, "Unknown connection type");
            return -1;
    }

    if (sd_channel_write_protobuf(channel, &conntype.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not send connection type");
        return -1;
    }

    return 0;
}

int sd_proto_receive_connection_type(enum sd_connection_type *out,
        struct sd_channel *channel)
{
    ConnectionInitiationMessage *initiation;
    int ret = 0;;

    if (sd_channel_receive_protobuf(channel,
                (ProtobufCMessageDescriptor *) &connection_initiation_message__descriptor,
                (ProtobufCMessage **) &initiation) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Failed receiving connection type");
        return -1;
    }

    switch (initiation->type) {
        case CONNECTION_INITIATION_MESSAGE__TYPE__QUERY:
            *out = SD_CONNECTION_TYPE_QUERY;
            break;
        case CONNECTION_INITIATION_MESSAGE__TYPE__REQUEST:
            *out = SD_CONNECTION_TYPE_REQUEST;
            break;
        case CONNECTION_INITIATION_MESSAGE__TYPE__CONNECT:
            *out = SD_CONNECTION_TYPE_CONNECT;
            break;
        case _CONNECTION_INITIATION_MESSAGE__TYPE_IS_INT_SIZE:
        default:
            ret = -1;
            break;
    }

    connection_initiation_message__free_unpacked(initiation, NULL);

    return ret;
}

int sd_proto_initiate_session(struct sd_channel *channel, int sessionid)
{
    SessionInitiationMessage initiation = SESSION_INITIATION_MESSAGE__INIT;

    initiation.sessionid = sessionid;
    if (sd_channel_write_protobuf(channel, &initiation.base) < 0 ) {
        sd_log(LOG_LEVEL_ERROR, "Could not initiate session");
        return -1;
    }

    return 0;
}

int sd_proto_handle_session(struct sd_channel *channel,
        const struct sd_sign_key_public *remote_key,
        struct sd_service *service,
        struct sd_service_session *sessions,
        struct cfg *cfg)
{
    SessionInitiationMessage *initiation;
    struct sd_service_session *session, *prev = NULL;
    struct service_args args;

    if (sd_channel_receive_protobuf(channel,
                &session_initiation_message__descriptor,
                (ProtobufCMessage **) &initiation) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not receive connection initiation");
        return -1;
    }

    for (session = sessions; session; session = session->next) {
        if (session->sessionid == initiation->sessionid &&
                memcmp(remote_key->data, session->identity.data, sizeof(remote_key->data)) == 0)
            break;
        prev = session;
    }
    session_initiation_message__free_unpacked(initiation, NULL);

    if (session == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Could not find session for client");
        return -1;
    }

    if (prev == NULL)
        sessions = session->next;
    else
        prev->next = session->next;

    session->next = NULL;
    args.cfg = cfg;
    args.channel = channel;
    args.session = session;
    args.service = service;
    spawn(handle_service, &args);

    sd_service_parameters_free(session->parameters, session->nparameters);
    free(session);

    return 0;
}

int sd_proto_send_request(struct sd_service_session *out,
        struct sd_channel *channel,
        const struct sd_sign_key_public *requester,
        const struct sd_service_parameter *params, size_t nparams)
{
    SessionRequestMessage request = SESSION_REQUEST_MESSAGE__INIT;
    SessionMessage *session;
    size_t i;

    memset(out, 0, sizeof(struct sd_service_session));

    request.identity.data = (uint8_t *) requester->data;
    request.identity.len = sizeof(requester->data);

    if (nparams) {
        Parameter **parameters = malloc(sizeof(Parameter *) * nparams);

        for (i = 0; i < nparams; i++) {
            Parameter *parameter = malloc(sizeof(Parameter));
            parameter__init(parameter);

            parameter->key = (char *) params[i].key;
            parameter->values = (char **) params[i].values;
            parameter->n_values = params[i].nvalues;

            parameters[i] = parameter;
        }

        request.parameters = parameters;
        request.n_parameters = nparams;
    } else {
        request.parameters = NULL;
        request.n_parameters = 0;
    }

    if (sd_channel_write_protobuf(channel, &request.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send connection request");
        return -1;
    }

    if (sd_channel_receive_protobuf(channel,
            &session_message__descriptor,
            (ProtobufCMessage **) &session) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive session");
        return -1;
    }

    out->sessionid = session->sessionid;
    memcpy(out->identity.data, requester->data, sizeof(out->identity.data));

    return 0;
}

int sd_proto_send_query(struct sd_channel *channel,
        struct sd_sign_key_public *remote_key)
{
    QueryResults *result;
    char pk[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    size_t i, j;

    if (sd_channel_receive_protobuf(channel, &query_results__descriptor,
            (ProtobufCMessage **) &result) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not receive query results");
        return -1;
    }

    sodium_bin2hex(pk, sizeof(pk),
            remote_key->data, sizeof(remote_key->data));

    printf("%s\n"
           "\tname:     %s\n"
           "\tcategory: %s\n"
           "\ttype:     %s\n"
           "\tversion:  %s\n"
           "\tlocation: %s\n"
           "\tport:     %s\n",
           pk,
           result->name,
           result->category,
           result->type,
           result->version,
           result->location,
           result->port);

    for (i = 0; i < result->n_parameters; i++) {
        Parameter *param = result->parameters[i];
        printf("\tparam:    %s\n", param->key);

        for (j = 0; j < param->n_values; j++)
            printf("\t          %s\n", param->values[j]);
    }

    query_results__free_unpacked(result, NULL);

    return 0;
}

int sd_proto_answer_query(struct sd_channel *channel,
        const struct sd_service *service,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist)
{
    QueryResults results = QUERY_RESULTS__INIT;
    Parameter **parameters;
    const struct sd_service_parameter *params;
    struct sd_sign_key_public remote_key;
    int i, n;

    if (!is_whitelisted(&remote_key, whitelist, nwhitelist)) {
        sd_log(LOG_LEVEL_ERROR, "Received connection from unknown signature key");
        return -1;
    }

    results.name = service->name;
    results.category = service->category;
    results.type = service->type;
    results.version = (char *) service->version();
    results.location = service->location;
    results.port = service->port;

    n = service->parameters(&params);
    parameters = malloc(sizeof(Parameter *) * n);
    for (i = 0; i < n; i++) {
        Parameter *parameter = malloc(sizeof(Parameter));
        parameter__init(parameter);

        parameter->key = (char *) params[i].key;
        parameter->n_values  = params[i].nvalues;
        parameter->values = (char **) params[i].values;

        parameters[i] = parameter;
    }
    results.parameters = parameters;
    results.n_parameters = n;

    if (sd_channel_write_protobuf(channel, (ProtobufCMessage *) &results) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not send query results");
        return -1;
    }

    return 0;
}

int sd_proto_answer_request(struct sd_service_session **out,
        struct sd_channel *channel,
        const struct sd_sign_key_public *remote_key,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist)
{
    SessionRequestMessage *request;
    SessionMessage session_message = SESSION_MESSAGE__INIT;
    struct sd_sign_key_public identity_key;
    struct sd_sign_key_hex identity_hex;
    struct sd_service_parameter *params;
    struct sd_service_session *session;

    if (!is_whitelisted(remote_key, whitelist, nwhitelist)) {
        sd_log(LOG_LEVEL_ERROR, "Received connection from unknown signature key");
        return -1;
    }

    if (sd_channel_receive_protobuf(channel,
            &session_request_message__descriptor,
            (ProtobufCMessage **) &request) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive request");
        return -1;
    }

    if (sd_sign_key_public_from_bin(&identity_key,
                request->identity.data, request->identity.len) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to parse identity key");
        return -1;
    }

    if (convert_params(&params, request) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to convert parameters");
        return -1;
    }
    session_request_message__free_unpacked(request, NULL);

    session_message.sessionid = randombytes_random();

    if (sd_channel_write_protobuf(channel, &session_message.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send connection session");
        return -1;
    }

    session = malloc(sizeof(struct sd_service_session));
    session->sessionid = session_message.sessionid;
    session->parameters = params;
    session->nparameters = request->n_parameters;
    memcpy(session->identity.data, identity_key.data, sizeof(session->identity.data));
    session->next = NULL;

    sd_sign_key_hex_from_key(&identity_hex, &identity_key);
    sd_log(LOG_LEVEL_DEBUG, "Created session %lu for %s", session_message.sessionid,
            identity_hex.data);

    *out = session;

    return 0;
}

static int is_whitelisted(const struct sd_sign_key_public *key,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist)
{
    uint32_t i;

    if (nwhitelist == 0) {
        return 1;
    }

    for (i = 0; i < nwhitelist; i++) {
        if (!memcmp(key->data, whitelist[i].data, sizeof(key->data))) {
            return 1;
        }
    }

    return 0;
}

static int convert_params(struct sd_service_parameter **out, const SessionRequestMessage *msg)
{
    struct sd_service_parameter *params;
    size_t i, j;

    *out = NULL;

    params = malloc(sizeof(struct sd_service_parameter) * msg->n_parameters);
    for (i = 0; i < msg->n_parameters; i++) {
        Parameter *msgparam = msg->parameters[i];

        params[i].key = strdup(msgparam->key);
        params[i].values = malloc(sizeof(char *) * msgparam->n_values);

        for (j = 0; j < msgparam->n_values; j++) {
            params[i].values[j] = strdup(msgparam->values[j]);
        }
        params[i].nvalues = msgparam->n_values;
    }

    *out = params;

    return 0;
}

static void handle_service(void *payload)
{
    struct service_args *args = (struct service_args *) payload;

    if (args->service->handle(args->channel, args->session, args->cfg) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Service could not handle connection");
        exit(-1);
    }

    exit(0);
}
