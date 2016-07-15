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
#include "lib/parameter.h"
#include "lib/session.h"

#include "proto/connect.pb-c.h"

#include "proto.h"

static ssize_t convert_params(struct sd_parameter **out,
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

int sd_proto_initiate_session(struct sd_channel *channel,
        const struct sd_cap *cap)
{
    SessionInitiationMessage initiation = SESSION_INITIATION_MESSAGE__INIT;
    SessionResult *result = NULL;
    int ret = 0;

    initiation.capability = malloc(sizeof(CapabilityMessage));
    if (sd_cap_to_protobuf(initiation.capability, cap) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not read capability");
        ret = -1;
        goto out;
    }

    if (sd_channel_write_protobuf(channel, &initiation.base) < 0 ) {
        sd_log(LOG_LEVEL_ERROR, "Could not initiate session");
        ret = -1;
        goto out;
    }

    if (sd_channel_receive_protobuf(channel,
                &session_result__descriptor,
                (ProtobufCMessage **) &result) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Could not receive session OK");
        ret = -1;
        goto out;
    }

    if (result->result != 0) {
        ret = -1;
        goto out;
    }

out:
    if (initiation.capability)
        capability_message__free_unpacked(initiation.capability, NULL);
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
    struct sd_cap cap;
    int err;

    memset(&session, 0, sizeof(session));

    if ((err = sd_channel_receive_protobuf(channel,
                &session_initiation_message__descriptor,
                (ProtobufCMessage **) &initiation)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Could not receive connection initiation");
        goto out;
    }

    if (sd_cap_from_protobuf(&cap, initiation->capability) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not read capability");
        err = -1;
        goto out_notify;
    }

    if (sd_caps_verify(&cap, remote_key, SD_CAP_RIGHT_EXEC) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not authorize session initiation");
        err = -1;
        goto out_notify;
    }

    if ((err = sd_sessions_remove(&session, cap.objectid)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not find session for client");
        goto out_notify;
    }

out_notify:
    msg.result = err;
    if (sd_channel_write_protobuf(channel, &msg.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not send session ack");
        goto out;
    }

    if (err)
        goto out;

    if ((err = service->handle(channel, remote_key, &session, cfg)) < 0) {
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

int sd_proto_send_request(struct sd_cap *invoker_cap,
        struct sd_cap *requester_cap,
        struct sd_channel *channel,
        const struct sd_sign_key_public *invoker,
        const struct sd_parameter *params, size_t nparams)
{
    SessionRequestMessage request = SESSION_REQUEST_MESSAGE__INIT;
    SessionMessage *session = NULL;
    Parameter **parameters = NULL;
    int err = -1;

    request.invoker.data = (uint8_t *) invoker->data;
    request.invoker.len = sizeof(invoker->data);
    request.n_parameters = sd_parameters_to_proto(&request.parameters, params, nparams);

    if (sd_channel_write_protobuf(channel, &request.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send connection request");
        goto out;
    }

    if (sd_channel_receive_protobuf(channel,
            &session_message__descriptor,
            (ProtobufCMessage **) &session) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive session");
        goto out;
    }

    if (sd_cap_from_protobuf(invoker_cap, session->invoker_cap) < 0 ||
            sd_cap_from_protobuf(requester_cap, session->requester_cap) <0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to read capabilities");
        goto out;
    }

    err = 0;

out:
    if (session)
        session_message__free_unpacked(session, NULL);

    sd_parameters_proto_free(parameters, nparams);

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
        const struct sd_service *service)
{
    ServiceDescription results = SERVICE_DESCRIPTION__INIT;
    Parameter **parameters;
    const struct sd_parameter *params;
    int i, n, err;

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

    sd_parameters_free(results->params, results->nparams);
    results->params = NULL;
    results->nparams = 0;
}

static int create_cap(CapabilityMessage **out, uint32_t objectid, uint32_t rights, const struct sd_sign_key_public *key)
{
    CapabilityMessage *msg;
    struct sd_cap cap;

    if (sd_caps_create_reference(&cap, objectid, rights, key) < 0)
        return -1;

    msg = malloc(sizeof(CapabilityMessage));
    if (sd_cap_to_protobuf(msg, &cap) < 0) {
        free(msg);
        return -1;
    }

    *out = msg;

    return 0;
}

int sd_proto_answer_request(struct sd_channel *channel,
        const struct sd_sign_key_public *remote_key)
{
    SessionRequestMessage *request = NULL;
    SessionMessage session_message = SESSION_MESSAGE__INIT;
    struct sd_sign_key_public identity_key;
    struct sd_parameter *params = NULL;
    ssize_t nparams = 0;
    uint32_t sessionid;
    int err = -1;

    if (sd_channel_receive_protobuf(channel,
            &session_request_message__descriptor,
            (ProtobufCMessage **) &request) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive request");
        goto out;
    }

    if (sd_sign_key_public_from_bin(&identity_key,
                request->invoker.data, request->invoker.len) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to parse invoker key");
        goto out;
    }

    if ((nparams = convert_params(&params,
                    request->parameters, request->n_parameters)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to convert parameters");
        goto out;
    }

    if (sd_sessions_add(&sessionid, params, nparams) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to add session");
        goto out;
    }

    if (sd_caps_add(sessionid) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to add internal capability");
        goto out;
    }

    if (create_cap(&session_message.invoker_cap, sessionid, SD_CAP_RIGHT_EXEC | SD_CAP_RIGHT_TERM, &identity_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to add invoker capability");
        goto out;
    }
    if (create_cap(&session_message.requester_cap, sessionid, SD_CAP_RIGHT_TERM, remote_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to add invoker capability");
        goto out;
    }

    if (sd_channel_write_protobuf(channel, &session_message.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send connection session");
        sd_caps_delete(sessionid);
        goto out;
    }

    err = 0;

out:
    sd_parameters_free(params, nparams);

    if (session_message.invoker_cap)
        capability_message__free_unpacked(session_message.invoker_cap, NULL);
    if (session_message.requester_cap)
        capability_message__free_unpacked(session_message.requester_cap, NULL);
    if (request)
        session_request_message__free_unpacked(request, NULL);

    return err;
}

int sd_proto_initiate_termination(struct sd_channel *channel,
        const struct sd_cap *cap)
{
    SessionTerminationMessage msg = SESSION_TERMINATION_MESSAGE__INIT;
    int err = 0;

    msg.capability = malloc(sizeof(CapabilityMessage));
    if ((err = sd_cap_to_protobuf(msg.capability, cap)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to write termination message");
        goto out;
    }

    if ((err = sd_channel_write_protobuf(channel, &msg.base)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to write termination message");
        goto out;
    }

out:
    capability_message__free_unpacked(msg.capability, NULL);

    return err;
}

int sd_proto_handle_termination(struct sd_channel *channel,
        const struct sd_sign_key_public *remote_key)
{
    SessionTerminationMessage *msg = NULL;
    struct sd_session session;
    struct sd_cap cap;
    int err = -1;

    if (sd_channel_receive_protobuf(channel,
            &session_termination_message__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive termination protobuf");
        goto out;
    }

    /* If session could not be found we have nothing to do */
    if (sd_sessions_find(&session, msg->capability->objectid) < 0) {
        goto out;
    }

    if (sd_cap_from_protobuf(&cap, msg->capability) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Received invalid capability");
        goto out;
    }

    if (sd_caps_verify(&cap, remote_key, SD_CAP_RIGHT_TERM) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Received unauthorized request");
        goto out;
    }

    if (sd_sessions_remove(NULL, cap.objectid) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to terminate session");
        goto out;
    }

    err = 0;

out:
    if (msg)
        session_termination_message__free_unpacked(msg, NULL);

    return err;
}

static ssize_t convert_params(struct sd_parameter **out,
        Parameter **parameters, size_t nparams)
{
    struct sd_parameter *params;
    size_t i;

    *out = NULL;

    params = malloc(sizeof(struct sd_parameter) * nparams);
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
