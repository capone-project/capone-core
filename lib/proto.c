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
#include "lib/session.h"

#include "proto/connect.pb-c.h"

#include "proto.h"

static int is_whitelisted(const struct sd_sign_key_public *key,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist);
static int convert_params(struct sd_service_parameter **out,
        Parameter **params,
        size_t nparams);

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
        const struct sd_service *service,
        const struct cfg *cfg)
{
    SessionInitiationMessage *initiation;
    struct sd_session session;

    if (sd_channel_receive_protobuf(channel,
                &session_initiation_message__descriptor,
                (ProtobufCMessage **) &initiation) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not receive connection initiation");
        return -1;
    }

    if (sd_sessions_remove(&session, initiation->sessionid, remote_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not find session for client");
        return -1;
    }

    if (service->handle(channel, &session, cfg) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Service could not handle connection");
        return -1;
    }

    sd_session_free(&session);

    return 0;
}

int sd_proto_send_request(struct sd_session *out,
        struct sd_channel *channel,
        const struct sd_sign_key_public *requester,
        const struct sd_service_parameter *params, size_t nparams)
{
    SessionRequestMessage request = SESSION_REQUEST_MESSAGE__INIT;
    SessionMessage *session;
    size_t i;

    memset(out, 0, sizeof(struct sd_session));

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

int sd_proto_send_query(struct sd_query_results *out,
        struct sd_channel *channel)
{
    QueryResults *msg;
    struct sd_query_results results;

    if (sd_channel_receive_protobuf(channel, &query_results__descriptor,
            (ProtobufCMessage **) &msg) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not receive query results");
        return -1;
    }

    results.name = msg->name;
    msg->name = NULL;
    results.category = msg->category;
    msg->category = NULL;
    results.type = msg->type;
    msg->type = NULL;
    results.version = msg->version;
    msg->version = NULL;
    results.location = msg->location;
    msg->location = NULL;
    results.port = msg->port;
    msg->port = NULL;

    convert_params(&results.params, msg->parameters, msg->n_parameters);
    results.nparams = msg->n_parameters;

    query_results__free_unpacked(msg, NULL);

    memcpy(out, &results, sizeof(*out));

    return 0;
}

int sd_proto_answer_query(struct sd_channel *channel,
        const struct sd_service *service,
        const struct sd_sign_key_public *remote_key,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist)
{
    QueryResults results = QUERY_RESULTS__INIT;
    Parameter **parameters;
    const struct sd_service_parameter *params;
    int i, n;

    if (!is_whitelisted(remote_key, whitelist, nwhitelist)) {
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

void sd_query_results_free(struct sd_query_results *results)
{
    sd_service_parameters_free(results->params, results->nparams);
}

int sd_proto_answer_request(struct sd_channel *channel,
        const struct sd_sign_key_public *remote_key,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist)
{
    SessionRequestMessage *request = NULL;
    SessionMessage session_message = SESSION_MESSAGE__INIT;
    struct sd_sign_key_public identity_key;
    struct sd_service_parameter *params;

    if (!is_whitelisted(remote_key, whitelist, nwhitelist)) {
        sd_log(LOG_LEVEL_ERROR, "Received connection from unknown signature key");
        goto out_err;
    }

    if (sd_channel_receive_protobuf(channel,
            &session_request_message__descriptor,
            (ProtobufCMessage **) &request) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive request");
        goto out_err;
    }

    if (sd_sign_key_public_from_bin(&identity_key,
                request->identity.data, request->identity.len) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to parse identity key");
        goto out_err;
    }

    if (convert_params(&params, request->parameters, request->n_parameters) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to convert parameters");
        goto out_err;
    }

    session_message.sessionid = randombytes_random();

    if (sd_channel_write_protobuf(channel, &session_message.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send connection session");
        goto out_err;
    }

    sd_sessions_add(session_message.sessionid, &identity_key, params, request->n_parameters);

    session_request_message__free_unpacked(request, NULL);
    return 0;

out_err:
    if (request != NULL)
        session_request_message__free_unpacked(request, NULL);
    return -1;
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

static int convert_params(struct sd_service_parameter **out,
        Parameter **parameters, size_t nparams)
{
    struct sd_service_parameter *params;
    size_t i, j;

    *out = NULL;

    params = malloc(sizeof(struct sd_service_parameter) * nparams);
    for (i = 0; i < nparams; i++) {
        Parameter *msgparam = parameters[i];

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
