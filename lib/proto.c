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

#include "capone/common.h"
#include "capone/channel.h"
#include "capone/log.h"
#include "capone/parameter.h"
#include "capone/session.h"
#include "capone/proto.h"

#include "capone/proto/connect.pb-c.h"

static ssize_t convert_params(struct cpn_parameter **out,
        Parameter **params,
        size_t nparams);

int cpn_proto_initiate_connection(struct cpn_channel *channel,
        const char *host,
        const char *port,
        const struct cpn_sign_key_pair *local_keys,
        const struct cpn_sign_key_public *remote_key,
        enum cpn_connection_type type)
{
    ConnectionInitiationMessage conntype = CONNECTION_INITIATION_MESSAGE__INIT;

    if (cpn_channel_init_from_host(channel, host, port, CPN_CHANNEL_TYPE_TCP) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initialize channel");
        return -1;
    }

    if (cpn_channel_connect(channel) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not connect to server");
        return -1;
    }

    if (cpn_proto_initiate_encryption(channel, local_keys, remote_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to initiate encryption");
        return -1;
    }

    switch (type) {
        case CPN_CONNECTION_TYPE_CONNECT:
            conntype.type = CONNECTION_INITIATION_MESSAGE__TYPE__CONNECT;
            break;
        case CPN_CONNECTION_TYPE_REQUEST:
            conntype.type = CONNECTION_INITIATION_MESSAGE__TYPE__REQUEST;
            break;
        case CPN_CONNECTION_TYPE_QUERY:
            conntype.type = CONNECTION_INITIATION_MESSAGE__TYPE__QUERY;
            break;
        case CPN_CONNECTION_TYPE_TERMINATE:
            conntype.type = CONNECTION_INITIATION_MESSAGE__TYPE__TERMINATE;
            break;
        default:
            cpn_log(LOG_LEVEL_ERROR, "Unknown connection type");
            return -1;
    }

    if (cpn_channel_write_protobuf(channel, &conntype.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send connection type");
        return -1;
    }

    return 0;
}

int cpn_proto_receive_connection_type(enum cpn_connection_type *out,
        struct cpn_channel *channel)
{
    ConnectionInitiationMessage *initiation;
    int ret = 0;;

    if (cpn_channel_receive_protobuf(channel,
                (ProtobufCMessageDescriptor *) &connection_initiation_message__descriptor,
                (ProtobufCMessage **) &initiation) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Failed receiving connection type");
        return -1;
    }

    switch (initiation->type) {
        case CONNECTION_INITIATION_MESSAGE__TYPE__QUERY:
            *out = CPN_CONNECTION_TYPE_QUERY;
            break;
        case CONNECTION_INITIATION_MESSAGE__TYPE__REQUEST:
            *out = CPN_CONNECTION_TYPE_REQUEST;
            break;
        case CONNECTION_INITIATION_MESSAGE__TYPE__CONNECT:
            *out = CPN_CONNECTION_TYPE_CONNECT;
            break;
        case CONNECTION_INITIATION_MESSAGE__TYPE__TERMINATE:
            *out = CPN_CONNECTION_TYPE_TERMINATE;
            break;
        case _CONNECTION_INITIATION_MESSAGE__TYPE_IS_INT_SIZE:
        default:
            ret = -1;
            break;
    }

    connection_initiation_message__free_unpacked(initiation, NULL);

    return ret;
}

int cpn_proto_initiate_session(struct cpn_channel *channel,
        const struct cpn_cap *cap)
{
    SessionInitiationMessage initiation = SESSION_INITIATION_MESSAGE__INIT;
    SessionResult *result = NULL;
    int ret = 0;

    initiation.capability = malloc(sizeof(CapabilityMessage));
    if (cpn_cap_to_protobuf(initiation.capability, cap) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not read capability");
        ret = -1;
        goto out;
    }

    if (cpn_channel_write_protobuf(channel, &initiation.base) < 0 ) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initiate session");
        ret = -1;
        goto out;
    }

    if (cpn_channel_receive_protobuf(channel,
                &session_result__descriptor,
                (ProtobufCMessage **) &result) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Could not receive session OK");
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

int cpn_proto_handle_session(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key,
        const struct cpn_service *service,
        const struct cpn_cfg *cfg)
{
    SessionInitiationMessage *initiation = NULL;
    SessionResult msg = SESSION_RESULT__INIT;
    struct cpn_session session;
    struct cpn_cap cap;
    int err;

    memset(&session, 0, sizeof(session));

    if ((err = cpn_channel_receive_protobuf(channel,
                &session_initiation_message__descriptor,
                (ProtobufCMessage **) &initiation)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Could not receive connection initiation");
        goto out;
    }

    if (cpn_cap_from_protobuf(&cap, initiation->capability) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not read capability");
        err = -1;
        goto out_notify;
    }

    if (cpn_caps_verify(&cap, remote_key, CPN_CAP_RIGHT_EXEC) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not authorize session initiation");
        err = -1;
        goto out_notify;
    }

    if ((err = cpn_sessions_remove(&session, cap.objectid)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not find session for client");
        goto out_notify;
    }

out_notify:
    msg.result = err;
    if (cpn_channel_write_protobuf(channel, &msg.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send session ack");
        goto out;
    }

    if (err)
        goto out;

    if ((err = service->handle(channel, remote_key, &session, cfg)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Service could not handle connection");
        goto out;
    }

out:
    if (initiation) {
        session_initiation_message__free_unpacked(initiation, NULL);
        cpn_session_free(&session);
    }

    return 0;
}

int cpn_proto_send_request(struct cpn_cap *invoker_cap,
        struct cpn_cap *requester_cap,
        struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker,
        const struct cpn_parameter *params, size_t nparams)
{
    SessionRequestMessage request = SESSION_REQUEST_MESSAGE__INIT;
    SessionMessage *session = NULL;
    Parameter **parameters = NULL;
    int err = -1;
    size_t i;

    request.invoker.data = (uint8_t *) invoker->data;
    request.invoker.len = sizeof(invoker->data);
    request.n_parameters = cpn_parameters_to_proto(&request.parameters, params, nparams);

    if (cpn_channel_write_protobuf(channel, &request.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send connection request");
        goto out;
    }

    if (cpn_channel_receive_protobuf(channel,
            &session_message__descriptor,
            (ProtobufCMessage **) &session) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive session");
        goto out;
    }

    if (cpn_cap_from_protobuf(invoker_cap, session->invoker_cap) < 0 ||
            cpn_cap_from_protobuf(requester_cap, session->requester_cap) <0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to read capabilities");
        goto out;
    }

    err = 0;

out:
    if (session)
        session_message__free_unpacked(session, NULL);
    for (i = 0; i < request.n_parameters; i++)
        parameter__free_unpacked(request.parameters[i], NULL);
    free(request.parameters);

    cpn_parameters_proto_free(parameters, nparams);

    return err;
}

int cpn_proto_send_query(struct cpn_query_results *out,
        struct cpn_channel *channel)
{
    ServiceDescription *msg;
    struct cpn_query_results results;

    memset(out, 0, sizeof(struct cpn_query_results));

    if (cpn_channel_receive_protobuf(channel, &service_description__descriptor,
            (ProtobufCMessage **) &msg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not receive query results");
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

int cpn_proto_answer_query(struct cpn_channel *channel,
        const struct cpn_service *service)
{
    ServiceDescription results = SERVICE_DESCRIPTION__INIT;
    Parameter **parameters;
    const struct cpn_parameter *params;
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

    if ((err = cpn_channel_write_protobuf(channel, (ProtobufCMessage *) &results)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send query results");
        goto out;
    }

out:
    for (i = 0; i < n; i++) {
        free(parameters[i]);
    }
    free(parameters);

    return err;
}

void cpn_query_results_free(struct cpn_query_results *results)
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

    cpn_parameters_free(results->params, results->nparams);
    results->params = NULL;
    results->nparams = 0;
}

static int create_cap(CapabilityMessage **out, uint32_t objectid, uint32_t rights, const struct cpn_sign_key_public *key)
{
    CapabilityMessage *msg;
    struct cpn_cap cap;

    if (cpn_caps_create_reference(&cap, objectid, rights, key) < 0)
        return -1;

    msg = malloc(sizeof(CapabilityMessage));
    if (cpn_cap_to_protobuf(msg, &cap) < 0) {
        free(msg);
        return -1;
    }

    *out = msg;

    return 0;
}

int cpn_proto_answer_request(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key)
{
    SessionRequestMessage *request = NULL;
    SessionMessage session_message = SESSION_MESSAGE__INIT;
    struct cpn_sign_key_public identity_key;
    struct cpn_parameter *params = NULL;
    ssize_t nparams = 0;
    uint32_t sessionid;
    int err = -1;

    if (cpn_channel_receive_protobuf(channel,
            &session_request_message__descriptor,
            (ProtobufCMessage **) &request) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive request");
        goto out;
    }

    if (cpn_sign_key_public_from_bin(&identity_key,
                request->invoker.data, request->invoker.len) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to parse invoker key");
        goto out;
    }

    if ((nparams = convert_params(&params,
                    request->parameters, request->n_parameters)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to convert parameters");
        goto out;
    }

    if (cpn_sessions_add(&sessionid, params, nparams) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to add session");
        goto out;
    }

    if (cpn_caps_add(sessionid) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to add internal capability");
        goto out;
    }

    if (create_cap(&session_message.invoker_cap, sessionid, CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM, &identity_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to add invoker capability");
        goto out;
    }
    if (create_cap(&session_message.requester_cap, sessionid, CPN_CAP_RIGHT_TERM, remote_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to add invoker capability");
        goto out;
    }

    if (cpn_channel_write_protobuf(channel, &session_message.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send connection session");
        cpn_caps_delete(sessionid);
        goto out;
    }

    err = 0;

out:
    cpn_parameters_free(params, nparams);

    if (session_message.invoker_cap)
        capability_message__free_unpacked(session_message.invoker_cap, NULL);
    if (session_message.requester_cap)
        capability_message__free_unpacked(session_message.requester_cap, NULL);
    if (request)
        session_request_message__free_unpacked(request, NULL);

    return err;
}

int cpn_proto_initiate_termination(struct cpn_channel *channel,
        const struct cpn_cap *cap)
{
    SessionTerminationMessage msg = SESSION_TERMINATION_MESSAGE__INIT;
    int err = 0;

    msg.capability = malloc(sizeof(CapabilityMessage));
    if ((err = cpn_cap_to_protobuf(msg.capability, cap)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to write termination message");
        goto out;
    }

    if ((err = cpn_channel_write_protobuf(channel, &msg.base)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to write termination message");
        goto out;
    }

out:
    capability_message__free_unpacked(msg.capability, NULL);

    return err;
}

int cpn_proto_handle_termination(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key)
{
    SessionTerminationMessage *msg = NULL;
    struct cpn_session session;
    struct cpn_cap cap;
    int err = -1;

    if (cpn_channel_receive_protobuf(channel,
            &session_termination_message__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive termination protobuf");
        goto out;
    }

    /* If session could not be found we have nothing to do */
    if (cpn_sessions_find(&session, msg->capability->objectid) < 0) {
        goto out;
    }

    if (cpn_cap_from_protobuf(&cap, msg->capability) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid capability");
        goto out;
    }

    if (cpn_caps_verify(&cap, remote_key, CPN_CAP_RIGHT_TERM) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Received unauthorized request");
        goto out;
    }

    if (cpn_sessions_remove(NULL, cap.objectid) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to terminate session");
        goto out;
    }

    err = 0;

out:
    if (msg)
        session_termination_message__free_unpacked(msg, NULL);

    return err;
}

static ssize_t convert_params(struct cpn_parameter **out,
        Parameter **parameters, size_t nparams)
{
    struct cpn_parameter *params;
    size_t i;

    *out = NULL;

    if (nparams == 0)
        return 0;

    params = malloc(sizeof(struct cpn_parameter) * nparams);
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
