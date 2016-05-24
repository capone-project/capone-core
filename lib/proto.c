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
static ssize_t convert_params(struct sd_service_parameter **out,
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
        case SD_CONNECTION_TYPE_TERMINATE:
            conntype.type = CONNECTION_INITIATION_MESSAGE__TYPE__TERMINATE;
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
        case CONNECTION_INITIATION_MESSAGE__TYPE__TERMINATE:
            *out = SD_CONNECTION_TYPE_TERMINATE;
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
    SessionResult *result = NULL;
    int ret = 0;

    initiation.sessionid = sessionid;
    if (sd_channel_write_protobuf(channel, &initiation.base) < 0 ) {
        sd_log(LOG_LEVEL_ERROR, "Could not initiate session");
        return -1;
    }

    if (sd_channel_receive_protobuf(channel,
                &session_result__descriptor,
                (ProtobufCMessage **) &result) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Could not receive session OK");
        return -1;
    }

    if (result->result != 0) {
        ret = -1;
    }

    if (result)
        session_result__free_unpacked(result, NULL);

    return ret;
}

int sd_proto_handle_session(struct sd_channel *channel,
        const struct sd_sign_key_public *remote_key,
        const struct sd_service *service,
        const struct sd_cfg *cfg)
{
    SessionInitiationMessage *initiation = NULL;
    SessionResult msg = SESSION_RESULT__INIT;
    struct sd_session session;
    int err;

    memset(&session, 0, sizeof(session));

    if ((err = sd_channel_receive_protobuf(channel,
                &session_initiation_message__descriptor,
                (ProtobufCMessage **) &initiation)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Could not receive connection initiation");
        goto out;
    }

    if ((err = sd_sessions_remove(&session, initiation->sessionid, remote_key)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not find session for client");
    }

    msg.result = err;
    if (sd_channel_write_protobuf(channel, &msg.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not send session ack");
        goto out;
    }

    if (err)
        goto out;

    if ((err = service->handle(channel, &session, cfg)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Service could not handle connection");
        goto out;
    }

out:
    if (initiation) {
        session_initiation_message__free_unpacked(initiation, NULL);
        sd_session_free(&session);
    }

    return 0;
}

int sd_proto_send_request(uint32_t *sessionid,
        struct sd_channel *channel,
        const struct sd_sign_key_public *invoker,
        const struct sd_service_parameter *params, size_t nparams)
{
    SessionRequestMessage request = SESSION_REQUEST_MESSAGE__INIT;
    SessionMessage *session = NULL;
    Parameter **parameters = NULL;
    size_t i;
    int err;

    request.invoker.data = (uint8_t *) invoker->data;
    request.invoker.len = sizeof(invoker->data);

    if (nparams) {
        parameters = malloc(sizeof(Parameter *) * nparams);

        for (i = 0; i < nparams; i++) {
            Parameter *parameter = malloc(sizeof(Parameter));
            parameter__init(parameter);

            parameter->key = (char *) params[i].key;
            parameter->value = (char *) params[i].value;

            parameters[i] = parameter;
        }

        request.parameters = parameters;
        request.n_parameters = nparams;
    } else {
        request.parameters = NULL;
        request.n_parameters = 0;
    }

    if ((err = sd_channel_write_protobuf(channel, &request.base)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send connection request");
        goto out;
    }

    if ((err = sd_channel_receive_protobuf(channel,
            &session_message__descriptor,
            (ProtobufCMessage **) &session)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive session");
        goto out;
    }

    *sessionid = session->sessionid;

out:
    if (session)
        session_message__free_unpacked(session, NULL);

    if (parameters) {
        for (i = 0; i < nparams; i++) {
            free(parameters[i]);
        }
        free(parameters);
    }

    return err;
}

int sd_proto_send_query(struct sd_query_results *out,
        struct sd_channel *channel)
{
    ServiceDescription *msg;
    struct sd_query_results results;

    memset(out, 0, sizeof(struct sd_query_results));

    if (sd_channel_receive_protobuf(channel, &service_description__descriptor,
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

    service_description__free_unpacked(msg, NULL);

    memcpy(out, &results, sizeof(*out));

    return 0;
}

int sd_proto_answer_query(struct sd_channel *channel,
        const struct sd_service *service,
        const struct sd_sign_key_public *remote_key,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist)
{
    ServiceDescription results = SERVICE_DESCRIPTION__INIT;
    Parameter **parameters;
    const struct sd_service_parameter *params;
    int i, n, err;

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
        parameter->value = (char *) params[i].value;

        parameters[i] = parameter;
    }
    results.parameters = parameters;
    results.n_parameters = n;

    if ((err = sd_channel_write_protobuf(channel, (ProtobufCMessage *) &results)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not send query results");
        goto out;
    }

out:
    for (i = 0; i < n; i++) {
        free(parameters[i]);
    }
    free(parameters);

    return err;
}

void sd_query_results_free(struct sd_query_results *results)
{
    if (results == NULL)
        return;

    free(results->name);
    results->name = NULL;
    free(results->category);
    results->category = NULL;
    free(results->type);
    results->type = NULL;
    free(results->version);
    results->version = NULL;
    free(results->location);
    results->location = NULL;
    free(results->port);
    results->port = NULL;

    sd_service_parameters_free(results->params, results->nparams);
    results->params = NULL;
    results->nparams = 0;
}

int sd_proto_answer_request(struct sd_channel *channel,
        const struct sd_sign_key_public *remote_key,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist)
{
    SessionRequestMessage *request = NULL;
    SessionMessage session_message = SESSION_MESSAGE__INIT;
    struct sd_sign_key_public identity_key;
    struct sd_service_parameter *params = NULL;
    ssize_t nparams = 0;

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
                request->invoker.data, request->invoker.len) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to parse invoker key");
        goto out_err;
    }

    if ((nparams = convert_params(&params,
                    request->parameters, request->n_parameters)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to convert parameters");
        goto out_err;
    }

    session_message.sessionid = randombytes_random();

    if (sd_channel_write_protobuf(channel, &session_message.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send connection session");
        goto out_err;
    }

    if (sd_sessions_add(session_message.sessionid,
                remote_key, &identity_key, params, nparams) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to add session");
        goto out_err;
    }

    sd_service_parameters_free(params, nparams);
    session_request_message__free_unpacked(request, NULL);
    return 0;

out_err:
    sd_service_parameters_free(params, nparams);

    if (request != NULL)
        session_request_message__free_unpacked(request, NULL);
    return -1;
}

int sd_proto_initiate_termination(struct sd_channel *channel,
        int sessionid, const struct sd_sign_key_public *invoker)
{
    SessionTerminationMessage msg = SESSION_TERMINATION_MESSAGE__INIT;

    msg.sessionid  = sessionid;
    msg.identity.data = (uint8_t *) invoker->data;
    msg.identity.len = sizeof(invoker->data);

    if (sd_channel_write_protobuf(channel, &msg.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to write termination message");
        return -1;
    }

    return 0;
}

int sd_proto_handle_termination(struct sd_channel *channel,
        const struct sd_sign_key_public *remote_key)
{
    SessionTerminationMessage *msg = NULL;
    struct sd_sign_key_public invoker_pk;
    struct sd_session session;
    int err = 0;

    if (sd_channel_receive_protobuf(channel,
            &session_termination_message__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive termination protobuf");
        err = -1;
        goto out;
    }

    if (sd_sign_key_public_from_bin(&invoker_pk,
            msg->identity.data, msg->identity.len) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Termination protobuf contains invalid invoker");
        err = -1;
        goto out;
    }

    /* If session could not be found we have nothing to do */
    if (sd_sessions_find(&session, msg->sessionid, &invoker_pk) < 0) {
        goto out;
    }

    /* Skip if session issuer does not match our remote's identity */
    if (memcmp(&session.issuer, remote_key, sizeof(session.issuer))) {
        goto out;
    }

    if (sd_sessions_remove(NULL, msg->sessionid, &invoker_pk) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to terminate session");
        goto out;
    }

out:
    if (msg)
        session_termination_message__free_unpacked(msg, NULL);

    return err;
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

static ssize_t convert_params(struct sd_service_parameter **out,
        Parameter **parameters, size_t nparams)
{
    struct sd_service_parameter *params;
    size_t i;

    *out = NULL;

    params = malloc(sizeof(struct sd_service_parameter) * nparams);
    for (i = 0; i < nparams; i++) {
        Parameter *msgparam = parameters[i];

        params[i].key = strdup(msgparam->key);
        if (msgparam->value) {
            params[i].value = strdup(msgparam->value);
        } else {
            params[i].value = NULL;
        }
    }

    *out = params;

    return nparams;
}
