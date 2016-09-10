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

#include "capone/log.h"
#include "capone/proto.h"

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

int cpn_proto_initiate_session(struct cpn_channel *channel,
        uint32_t sessionid,
        const struct cpn_cap *cap)
{
    SessionInitiationMessage initiation = SESSION_INITIATION_MESSAGE__INIT;
    SessionResult *result = NULL;
    int ret = 0;

    initiation.identifier = sessionid;
    if (cpn_cap_to_protobuf(&initiation.capability, cap) < 0) {
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

int cpn_proto_send_request(uint32_t *sessionid,
        struct cpn_cap **cap,
        struct cpn_channel *channel,
        const struct ProtobufCMessage *params)
{
    SessionRequestMessage request = SESSION_REQUEST_MESSAGE__INIT;
    SessionMessage *session = NULL;
    int err = -1;

    if (params) {
        int len = protobuf_c_message_get_packed_size(params);
        request.parameters.data = malloc(len);
        request.parameters.len = len;
        protobuf_c_message_pack(params, request.parameters.data);
    }

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

    if (cpn_cap_from_protobuf(cap, session->cap) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to read capabilities");
        goto out;
    }

    *sessionid = session->identifier;

    err = 0;

out:
    if (session)
        session_message__free_unpacked(session, NULL);
    free(request.parameters.data);

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

    service_description__free_unpacked(msg, NULL);

    memcpy(out, &results, sizeof(*out));

    return 0;
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
}

int cpn_proto_initiate_termination(struct cpn_channel *channel,
        uint32_t sessionid, const struct cpn_cap *cap)
{
    SessionTerminationMessage msg = SESSION_TERMINATION_MESSAGE__INIT;
    int err = 0;

    msg.identifier = sessionid;
    if ((err = cpn_cap_to_protobuf(&msg.capability, cap)) < 0) {
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
