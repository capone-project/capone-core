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

#include "config.h"

#include "capone/buf.h"
#include "capone/client.h"
#include "capone/common.h"
#include "capone/log.h"

#include "capone/crypto/asymmetric.h"

#include "capone/proto/capone.pb-c.h"
#include "capone/proto/discovery.pb-c.h"
#include "capone/proto/encryption.pb-c.h"

extern int send_key_acknowledgement(struct cpn_channel *channel,
        const struct cpn_sign_keys *sign_keys,
        const struct cpn_asymmetric_pk *local_emph_key,
        const struct cpn_sign_pk *remote_sign_key,
        const struct cpn_asymmetric_pk *remote_emph_key);
extern int receive_key_acknowledgement(struct cpn_asymmetric_pk *out,
        struct cpn_channel *c,
        const struct cpn_sign_pk *local_sign_pk,
        const struct cpn_asymmetric_pk *local_emph_key,
        const struct cpn_sign_pk *remote_sign_pk);

static int initiate_encryption(struct cpn_channel *channel,
        const struct cpn_sign_keys *sign_keys,
        const struct cpn_sign_pk *remote_sign_key);

static int initiate_connection_type(struct cpn_channel *channel,
        ConnectionInitiationMessage__Type type)
{
    ConnectionInitiationMessage msg = CONNECTION_INITIATION_MESSAGE__INIT;

    msg.type = type;

    if (cpn_channel_write_protobuf(channel, &msg.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send connection type");
        return -1;
    }

    return 0;
}

int cpn_client_discovery_probe(struct cpn_channel *channel, const struct cpn_list *known_keys)
{
    DiscoverMessage msg = DISCOVER_MESSAGE__INIT;
    struct cpn_sign_pk *key;
    struct cpn_list_entry *it;
    size_t i, keys;
    int err;

    msg.version = CPN_PROTOCOL_VERSION;

    keys = cpn_list_count(known_keys);

    msg.n_known_keys = keys;
    if (keys > 0) {
        msg.known_keys = calloc(keys, sizeof(ProtobufCBinaryData));

        i = 0;
        cpn_list_foreach(known_keys, it, key) {
            msg.known_keys[i].len = sizeof(struct cpn_sign_pk);
            msg.known_keys[i].data = malloc(sizeof(struct cpn_sign_pk));
            memcpy(msg.known_keys[i].data, &key->data, sizeof(struct cpn_sign_pk));
            i++;
        }
    } else {
        msg.known_keys = NULL;
    }

    err = cpn_channel_write_protobuf(channel, &msg.base);

    for (i = 0; i < keys; i++) {
        free(msg.known_keys[i].data);
    }
    free(msg.known_keys);

    if (err)
        cpn_log(LOG_LEVEL_ERROR, "Unable to send discover: %s", strerror(errno));

    return err;
}

int cpn_client_discovery_handle_announce(struct cpn_discovery_results *out,
        struct cpn_channel *channel)
{
    struct cpn_discovery_results results;
    DiscoverResult *announce = NULL;
    int err = -1;
    uint32_t i;

    if (cpn_channel_receive_protobuf(channel,
                (ProtobufCMessageDescriptor *) &discover_result__descriptor,
                (ProtobufCMessage **) &announce) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive protobuf");
        goto out;
    }

    if (cpn_sign_pk_from_proto(&results.identity,
                announce->identity) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Invalid identity");
        goto out;
    }

    results.name = announce->name;
    announce->name = NULL;
    results.version = announce->version;

    results.nservices = announce->n_services;
    if (results.nservices) {
        results.services = malloc(sizeof(struct cpn_service) * results.nservices);
        for (i = 0; i < results.nservices; i++) {
            results.services[i].name = announce->services[i]->name;
            announce->services[i]->name = NULL;
            results.services[i].category = announce->services[i]->category;
            announce->services[i]->category = NULL;
            results.services[i].port = announce->services[i]->port;
        }
    } else {
        results.services = NULL;
    }

    memcpy(out, &results, sizeof(struct cpn_discovery_results));

    err = 0;

out:
    if (announce)
        discover_result__free_unpacked(announce, NULL);

    return err;
}

void cpn_discovery_results_clear(struct cpn_discovery_results *results)
{
    uint32_t i;

    if (results == NULL)
        return;

    for (i = 0; i < results->nservices; i++) {
        free(results->services[i].name);
        free(results->services[i].category);
    }

    free(results->name);
    free(results->services);
}

int cpn_client_connect(struct cpn_channel *channel,
        const char *host,
        uint32_t port,
        const struct cpn_sign_keys *local_keys,
        const struct cpn_sign_pk *remote_key)
{
    if (cpn_channel_init_from_host(channel, host, port, CPN_CHANNEL_TYPE_TCP) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initialize channel");
        return -1;
    }

    if (cpn_channel_connect(channel) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not connect to server");
        return -1;
    }

    if (initiate_encryption(channel, local_keys, remote_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to initiate encryption");
        return -1;
    }

    return 0;
}

int cpn_client_start_session(struct cpn_session **out,
        struct cpn_channel *channel,
        uint32_t sessionid,
        const struct cpn_cap *cap,
        const struct cpn_service_plugin *plugin)
{
    SessionConnectMessage connect = SESSION_CONNECT_MESSAGE__INIT;
    SessionConnectResult *result = NULL;
    ProtobufCMessage *params = NULL;
    struct cpn_session *session;
    int err = -1;

    if (initiate_connection_type(channel, CONNECTION_INITIATION_MESSAGE__TYPE__CONNECT) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initiate connection type");
        goto out;
    }

    connect.version = CPN_PROTOCOL_VERSION;
    connect.identifier = sessionid;
    if (cpn_cap_to_protobuf(&connect.capability, cap) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not read capability");
        goto out;
    }

    if (cpn_channel_write_protobuf(channel, &connect.base) < 0 ) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initiate session");
        goto out;
    }

    if (cpn_channel_receive_protobuf(channel,
                &session_connect_result__descriptor,
                (ProtobufCMessage **) &result) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Could not receive session OK");
        goto out;
    }

    if (result->error || !result->result) {
        cpn_log(LOG_LEVEL_ERROR, "Server error while starting session");
        goto out;
    }

    if (plugin->params_desc) {
        params = protobuf_c_message_unpack(plugin->params_desc, NULL,
                result->result->parameters.len, result->result->parameters.data);
    }

    session = malloc(sizeof(struct cpn_session));
    session->parameters = params;
    session->identifier = sessionid;
    session->cap = cpn_cap_dup(cap);

    *out = session;

    err = 0;

out:
    if (connect.capability)
        capability_message__free_unpacked(connect.capability, NULL);
    if (result)
        session_connect_result__free_unpacked(result, NULL);

    return err;
}

int cpn_client_request_session(uint32_t *sessionid,
        struct cpn_cap **cap,
        struct cpn_channel *channel,
        const struct ProtobufCMessage *params)
{
    SessionRequestMessage request = SESSION_REQUEST_MESSAGE__INIT;
    SessionRequestResult *session = NULL;
    int err = -1;

    if (initiate_connection_type(channel, CONNECTION_INITIATION_MESSAGE__TYPE__REQUEST) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initiate connection type");
        goto out;
    }

    request.version = CPN_PROTOCOL_VERSION;
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
            &session_request_result__descriptor,
            (ProtobufCMessage **) &session) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive session");
        goto out;
    }

    if (session->error || !session->result) {
        cpn_log(LOG_LEVEL_ERROR, "Server error while requesting session");
        goto out;
    }

    if (cpn_cap_from_protobuf(cap, session->result->cap) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to read capabilities");
        goto out;
    }

    *sessionid = session->result->identifier;

    err = 0;

out:
    if (session)
        session_request_result__free_unpacked(session, NULL);
    free(request.parameters.data);

    return err;
}

int cpn_client_query_service(struct cpn_query_results *out,
        struct cpn_channel *channel)
{
    ServiceQueryMessage query = SERVICE_QUERY_MESSAGE__INIT;
    ServiceQueryResult *msg;
    struct cpn_query_results results;

    if (initiate_connection_type(channel, CONNECTION_INITIATION_MESSAGE__TYPE__QUERY) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initiate connection type");
        return -1;
    }

    query.version = CPN_PROTOCOL_VERSION;

    if (cpn_channel_write_protobuf(channel, &query.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send query");
        return -1;
    }

    if (cpn_channel_receive_protobuf(channel, &service_query_result__descriptor,
            (ProtobufCMessage **) &msg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not receive query results");
        return -1;
    }

    if (msg->error || !msg->result) {
        cpn_log(LOG_LEVEL_ERROR, "Query failed");
        return -1;
    }

    results.name = msg->result->name;
    msg->result->name = NULL;
    results.category = msg->result->category;
    msg->result->category = NULL;
    results.type = msg->result->type;
    msg->result->type = NULL;
    results.version = msg->result->version;
    results.location = msg->result->location;
    msg->result->location = NULL;
    results.port = msg->result->port;

    service_query_result__free_unpacked(msg, NULL);

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
    free(results->location);
    results->location = NULL;
}

int cpn_client_terminate_session(struct cpn_channel *channel,
        uint32_t sessionid, const struct cpn_cap *cap)
{
    SessionTerminationMessage msg = SESSION_TERMINATION_MESSAGE__INIT;
    SessionTerminationResult *result = NULL;
    int err = -1;

    if (initiate_connection_type(channel, CONNECTION_INITIATION_MESSAGE__TYPE__TERMINATE) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not initiate connection type");
        goto out;
    }

    msg.version = CPN_PROTOCOL_VERSION;
    msg.identifier = sessionid;
    if ((err = cpn_cap_to_protobuf(&msg.capability, cap)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to write termination message");
        goto out;
    }

    if ((err = cpn_channel_write_protobuf(channel, &msg.base)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to write termination message");
        goto out;
    }

    if ((err = cpn_channel_receive_protobuf(channel, &session_termination_result__descriptor,
                    (ProtobufCMessage **) &result)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to write termination message");
        goto out;
    }

    if (result->error) {
        cpn_log(LOG_LEVEL_ERROR, "Termination failed");
        goto out;
    }

    err = 0;

out:
    if (result)
        session_termination_result__free_unpacked(result, NULL);
    capability_message__free_unpacked(msg.capability, NULL);

    return err;
}

static int send_ephemeral_key(struct cpn_channel *channel,
        const struct cpn_sign_keys *sign_keys,
        const struct cpn_asymmetric_pk *encrypt_key)
{
    EncryptionInitiationMessage msg = ENCRYPTION_INITIATION_MESSAGE__INIT;
    IdentityMessage *identity = NULL;
    PublicKeyMessage *ephemeral = NULL;
    int err = -1;

    if (cpn_sign_pk_to_proto(&identity, &sign_keys->pk) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not generate identity message");
        goto out;
    }

    if (cpn_asymmetric_pk_to_proto(&ephemeral, encrypt_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not generate ephemeral key message");
        goto out;
    }

    msg.identity = identity;
    msg.ephemeral = ephemeral;

    if (cpn_channel_write_protobuf(channel, &msg.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send negotiation");
        goto out;
    }

    err = 0;

out:
    if (identity)
        identity_message__free_unpacked(identity, NULL);
    if (ephemeral)
        public_key_message__free_unpacked(ephemeral, NULL);

    return err;
}

static int initiate_encryption(struct cpn_channel *channel,
        const struct cpn_sign_keys *sign_keys,
        const struct cpn_sign_pk *remote_sign_key)
{
    struct cpn_asymmetric_keys emph_keys;
    struct cpn_asymmetric_pk remote_emph_key;
    struct cpn_symmetric_key shared_key;

    if (cpn_asymmetric_keys_generate(&emph_keys) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    if (send_ephemeral_key(channel, sign_keys, &emph_keys.pk) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send session key");
        return -1;
    }

    if (receive_key_acknowledgement(&remote_emph_key, channel,
                &sign_keys->pk, &emph_keys.pk, remote_sign_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        return -1;
    }

    if (send_key_acknowledgement(channel,
                sign_keys, &emph_keys.pk,
                remote_sign_key, &remote_emph_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send key verification");
        return -1;
    }

    if (cpn_symmetric_key_from_scalarmult(&shared_key, &emph_keys, &remote_emph_key, true) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to derive shared key");
        return -1;
    }

    cpn_memzero(&emph_keys, sizeof(emph_keys));

    if (cpn_channel_enable_encryption(channel, &shared_key, 0) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}
