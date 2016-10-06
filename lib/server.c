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

#include "config.h"

#include "capone/buf.h"
#include "capone/channel.h"
#include "capone/common.h"
#include "capone/log.h"
#include "capone/session.h"
#include "capone/server.h"

#include "capone/crypto/asymmetric.h"

#include "capone/proto/capone.pb-c.h"
#include "capone/proto/discovery.pb-c.h"
#include "capone/proto/encryption.pb-c.h"

int cpn_server_await_command(enum cpn_command *out,
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
            *out = CPN_COMMAND_QUERY;
            break;
        case CONNECTION_INITIATION_MESSAGE__TYPE__REQUEST:
            *out = CPN_COMMAND_REQUEST;
            break;
        case CONNECTION_INITIATION_MESSAGE__TYPE__CONNECT:
            *out = CPN_COMMAND_CONNECT;
            break;
        case CONNECTION_INITIATION_MESSAGE__TYPE__TERMINATE:
            *out = CPN_COMMAND_TERMINATE;
            break;
        case _CONNECTION_INITIATION_MESSAGE__TYPE_IS_INT_SIZE:
        default:
            ret = -1;
            break;
    }

    connection_initiation_message__free_unpacked(initiation, NULL);

    return ret;
}

int cpn_server_handle_discovery(struct cpn_channel *channel,
        const char *name,
        uint32_t nservices,
        const struct cpn_service *services,
        const struct cpn_sign_pk *local_key)
{
    DiscoverMessage *msg = NULL;
    DiscoverResult result = DISCOVER_RESULT__INIT;
    DiscoverResult__Service **service_messages = NULL;
    size_t i;
    int err = -1;

    if (cpn_channel_receive_protobuf(channel, &discover_message__descriptor,
            (ProtobufCMessage **) &msg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive envelope");
        goto out;
    }

    if (msg->version != CPN_PROTOCOL_VERSION) {
        cpn_log(LOG_LEVEL_ERROR, "Cannot handle discovery protocol version %"PRIu32,
                msg->version);
        goto out;
    }

    for (i = 0; i < msg->n_known_keys; i++) {
        if (msg->known_keys[i].len != sizeof(struct cpn_sign_pk))
            continue;
        if (memcmp(msg->known_keys[i].data, local_key->data, sizeof(struct cpn_sign_pk)))
            continue;
        cpn_log(LOG_LEVEL_DEBUG, "Skipping announce due to alreay being known");
        err = 0;
        goto out;
    }

    result.name = (char *) name;
    result.version = CPN_PROTOCOL_VERSION;
    cpn_sign_pk_to_proto(&result.identity, local_key);

    service_messages = malloc(sizeof(DiscoverResult__Service *) * nservices);
    for (i = 0; i < (size_t) nservices; i++) {
        service_messages[i] = malloc(sizeof(DiscoverResult__Service));
        discover_result__service__init(service_messages[i]);
        service_messages[i]->name = services[i].name;
        service_messages[i]->port = services[i].port;
        service_messages[i]->category = (char *) services[i].plugin->category;
    }
    result.services = service_messages;
    result.n_services = nservices;

    if (cpn_channel_write_protobuf(channel, &result.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not write announce message");
        goto out;
    }

    cpn_log(LOG_LEVEL_DEBUG, "Sent announce");
    err = 0;

out:
    if (msg)
        discover_message__free_unpacked(msg, NULL);
    if (service_messages) {
        for (i = 0; i < (size_t) nservices; i++)
            free(service_messages[i]);
        free(service_messages);
    }
    if (result.identity)
        identity_message__free_unpacked(result.identity, NULL);

    return err;
}

int cpn_server_handle_session(struct cpn_channel *channel,
        const struct cpn_sign_pk *remote_key,
        const struct cpn_service *service,
        const struct cpn_cfg *cfg)
{
    SessionConnectMessage *connect = NULL;
    SessionConnectResult msg = SESSION_CONNECT_RESULT__INIT;
    SessionConnectResult__Result result = SESSION_CONNECT_RESULT__RESULT__INIT;
    ErrorMessage error = ERROR_MESSAGE__INIT;
    struct cpn_session *session = NULL;
    struct cpn_cap *cap = NULL;
    int err = -1;

    if ((cpn_channel_receive_protobuf(channel,
                &session_connect_message__descriptor,
                (ProtobufCMessage **) &connect)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Could not receive connect");
        goto out;
    }

    if (connect->version != CPN_PROTOCOL_VERSION) {
        cpn_log(LOG_LEVEL_ERROR, "Cannot handle connect protocol version %"PRIu32,
                connect->version);
        error.code = ERROR_MESSAGE__ERROR_CODE__EVERSION;
        goto out_notify;
    }

    if (strcmp(connect->service_type, service->plugin->type)) {
        cpn_log(LOG_LEVEL_ERROR, "Received connect for service type %s on service %s",
                connect->service_type, service->plugin->type);
        error.code = ERROR_MESSAGE__ERROR_CODE__EINVAL;
        goto out_notify;
    }

    if (connect->service_version != service->plugin->version) {
        cpn_log(LOG_LEVEL_ERROR, "Cannot handle version %"PRIu32" on service %s",
                connect->service_version, service->plugin->type);
        error.code = ERROR_MESSAGE__ERROR_CODE__EVERSION;
        goto out_notify;
    }

    if (cpn_cap_from_protobuf(&cap, connect->capability) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not read capability");
        error.code = ERROR_MESSAGE__ERROR_CODE__EACCESS;
        goto out_notify;
    }

    if (cpn_sessions_find((const struct cpn_session **) &session, connect->identifier) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not find session for client");
        error.code = ERROR_MESSAGE__ERROR_CODE__ENOTFOUND;
        goto out_notify;
    }

    if (cpn_caps_verify(cap, &session->secret, remote_key, CPN_CAP_RIGHT_EXEC) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not authorize session connect");
        error.code = ERROR_MESSAGE__ERROR_CODE__EPERM;
        goto out_notify;
    }

    if ((err = cpn_sessions_remove(&session, connect->identifier)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not find session for client");
        error.code = ERROR_MESSAGE__ERROR_CODE__EUNKNOWN;
        goto out_notify;
    }

    if (session->parameters) {
        size_t len = protobuf_c_message_get_packed_size(session->parameters);

        result.parameters.len = len;
        result.parameters.data = malloc(len);
        protobuf_c_message_pack(session->parameters, result.parameters.data);
    }

    msg.result = &result;

    err = 0;

out_notify:
    if (err)
        msg.error = &error;

    if (cpn_channel_write_protobuf(channel, &msg.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send session ack");
        err = -1;
        goto out;
    }

    if (err)
        goto out;

    if ((err = service->plugin->server_fn(channel, remote_key, session, cfg)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Service could not handle connection");
        goto out;
    }

out:
    if (connect) {
        session_connect_message__free_unpacked(connect, NULL);
        cpn_session_free(session);
    }

    free(result.parameters.data);
    cpn_cap_free(cap);

    return err;
}

int cpn_server_handle_query(struct cpn_channel *channel,
        const struct cpn_service *service)
{
    ServiceQueryResult response = SERVICE_QUERY_RESULT__INIT;
    ServiceQueryResult__Result result = SERVICE_QUERY_RESULT__RESULT__INIT;
    ErrorMessage error = ERROR_MESSAGE__INIT;
    ServiceQueryMessage *msg = NULL;
    int err = -1;

    if (cpn_channel_receive_protobuf(channel, &service_query_message__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Could not receive query");
        goto out;
    }

    if (msg->version != CPN_PROTOCOL_VERSION) {
        cpn_log(LOG_LEVEL_ERROR, "Cannot handle query protocol version %"PRIu32,
                msg->version);
        error.code = ERROR_MESSAGE__ERROR_CODE__EVERSION;
        goto out_notify;
    }

    result.name = service->name;
    result.location = service->location;
    result.port = service->port;
    result.category = (char *) service->plugin->category;
    result.type = (char *) service->plugin->type;
    result.version = service->plugin->version;

    response.result = &result;

    err = 0;

out_notify:
    if (err)
        response.error = &error;

    if (cpn_channel_write_protobuf(channel, (ProtobufCMessage *) &response) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send query results");
        err = -1;
        goto out;
    }

out:
    if (msg)
        service_query_message__free_unpacked(msg, NULL);

    return err;
}

static int create_cap(CapabilityMessage **out,
        const struct cpn_cap_secret *secret,
        uint32_t rights, const struct cpn_sign_pk *key)
{
    CapabilityMessage *msg = NULL;
    struct cpn_cap *cap = NULL;
    int err = -1;

    if (cpn_cap_create_ref_for_secret(&cap, secret, rights, key) < 0)
        goto out;

    if (cpn_cap_to_protobuf(&msg, cap) < 0)
        goto out;

    *out = msg;
    err = 0;

out:
    if (err)
        free(msg);
    cpn_cap_free(cap);

    return err;
}

int cpn_server_handle_request(struct cpn_channel *channel,
        const struct cpn_sign_pk *remote_key,
        const struct cpn_service_plugin *service)
{
    SessionRequestMessage *request = NULL;
    ProtobufCMessage *parameters = NULL;
    SessionRequestResult response = SESSION_REQUEST_RESULT__INIT;
    SessionRequestResult__Result result = SESSION_REQUEST_RESULT__RESULT__INIT;
    ErrorMessage error = ERROR_MESSAGE__INIT;
    const struct cpn_session *session = NULL;
    int err = -1;

    if (cpn_channel_receive_protobuf(channel,
            &session_request_message__descriptor,
            (ProtobufCMessage **) &request) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive request");
        goto out;
    }

    if (request->version != CPN_PROTOCOL_VERSION) {
        cpn_log(LOG_LEVEL_ERROR, "Cannot handle request protocol version %"PRIu32,
                request->version);
        error.code = ERROR_MESSAGE__ERROR_CODE__EVERSION;
        goto out_notify;
    }

    if (service->params_desc) {
        if ((parameters = protobuf_c_message_unpack(service->params_desc, NULL,
                        request->parameters.len, request->parameters.data)) == NULL) {
            error.code = ERROR_MESSAGE__ERROR_CODE__EINVAL;
            goto out_notify;
        }
    }

    if (cpn_sessions_add(&session, parameters, remote_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to add session");
        error.code = ERROR_MESSAGE__ERROR_CODE__EUNKNOWN;
        goto out_notify;
    }

    if (create_cap(&result.cap, &session->secret,
                CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM, remote_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to add invoker capability");
        error.code = ERROR_MESSAGE__ERROR_CODE__EUNKNOWN;
        goto out_notify;
    }

    result.identifier = session->identifier;
    response.result = &result;

    err = 0;

out_notify:
    if (err)
        response.error = &error;

    if (cpn_channel_write_protobuf(channel, &response.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send connection session");
        if (session)
            cpn_sessions_remove(NULL, session->identifier);
        err = -1;
        goto out;
    }

out:
    if (result.cap)
        capability_message__free_unpacked(result.cap, NULL);
    if (request)
        session_request_message__free_unpacked(request, NULL);

    return err;
}

int cpn_server_handle_termination(struct cpn_channel *channel,
        const struct cpn_sign_pk *remote_key)
{
    SessionTerminationMessage *msg = NULL;
    SessionTerminationResult result = SESSION_TERMINATION_RESULT__INIT;
    ErrorMessage error = ERROR_MESSAGE__INIT;
    const struct cpn_session *session;
    struct cpn_cap *cap = NULL;
    int err = -1;

    if (cpn_channel_receive_protobuf(channel,
            &session_termination_message__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive termination protobuf");
        goto out;
    }

    if (msg->version != CPN_PROTOCOL_VERSION) {
        cpn_log(LOG_LEVEL_ERROR, "Cannot handle termination protocol version %"PRIu32,
                msg->version);
        error.code = ERROR_MESSAGE__ERROR_CODE__EVERSION;
        goto out_notify;
    }

    /* If session could not be found we have nothing to do */
    if (cpn_sessions_find(&session, msg->identifier) < 0) {
        error.code = ERROR_MESSAGE__ERROR_CODE__ENOTFOUND;
        goto out_notify;
    }

    if (cpn_cap_from_protobuf(&cap, msg->capability) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid capability");
        error.code = ERROR_MESSAGE__ERROR_CODE__EINVAL;
        goto out_notify;
    }

    if (cpn_caps_verify(cap, &session->secret, remote_key, CPN_CAP_RIGHT_TERM) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Received unauthorized request");
        error.code = ERROR_MESSAGE__ERROR_CODE__EPERM;
        goto out_notify;
    }

    if (cpn_sessions_remove(NULL, msg->identifier) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to terminate session");
        error.code = ERROR_MESSAGE__ERROR_CODE__EUNKNOWN;
        goto out_notify;
    }

    err = 0;

out_notify:
    if (err)
        result.error = &error;

    if (cpn_channel_write_protobuf(channel, &result.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send termination result");
        err = -1;
        goto out;
    }

out:
    if (msg)
        session_termination_message__free_unpacked(msg, NULL);
    cpn_cap_free(cap);

    return err;
}

int send_key_acknowledgement(struct cpn_channel *channel,
        const struct cpn_sign_keys *sign_keys,
        const struct cpn_asymmetric_pk *local_emph_key,
        const struct cpn_sign_pk *remote_sign_key,
        const struct cpn_asymmetric_pk *remote_emph_key)
{
    EncryptionAcknowledgementMessage msg = ENCRYPTION_ACKNOWLEDGEMENT_MESSAGE__INIT;
    IdentityMessage *identity = NULL;
    PublicKeyMessage *ephemeral = NULL;
    SignatureMessage *signature = NULL;
    struct cpn_buf sign_buf = CPN_BUF_INIT;
    struct cpn_sign_sig sig;
    int err = -1;

    cpn_buf_append_data(&sign_buf, sign_keys->pk.data, CPN_CRYPTO_SIGN_PKBYTES);
    cpn_buf_append_data(&sign_buf, local_emph_key->data, CPN_CRYPTO_ASYMMETRIC_PKBYTES);
    cpn_buf_append_data(&sign_buf, remote_emph_key->data, CPN_CRYPTO_ASYMMETRIC_PKBYTES);
    cpn_buf_append_data(&sign_buf, remote_sign_key->data, CPN_CRYPTO_ASYMMETRIC_PKBYTES);

    if (cpn_sign_sig(&sig, &sign_keys->sk, (uint8_t *) sign_buf.data, sign_buf.length) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to sign ephemeral key");
        goto out;
    }

    if (cpn_sign_pk_to_proto(&identity, &sign_keys->pk) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to generate identity message");
        goto out;
    }

    if (cpn_asymmetric_pk_to_proto(&ephemeral, local_emph_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to generate ephemeral key message");
        goto out;
    }

    if (cpn_sign_sig_to_proto(&signature, &sig) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to generate signature message");
        goto out;
    }

    msg.identity = identity;
    msg.ephemeral = ephemeral;
    msg.signature = signature;

    if (cpn_channel_write_protobuf(channel, &msg.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid ephemeral key signature");
        goto out;
    }

    err = 0;

out:
    if (identity)
        identity_message__free_unpacked(identity, NULL);
    if (ephemeral)
        public_key_message__free_unpacked(ephemeral, NULL);
    if (signature)
        signature_message__free_unpacked(signature, NULL);
    cpn_buf_clear(&sign_buf);

    return err;
}

static int receive_ephemeral_key(
        struct cpn_channel *channel,
        struct cpn_sign_pk *remote_sign_key,
        struct cpn_asymmetric_pk *remote_encrypt_key)
{
    EncryptionInitiationMessage *msg = NULL;
    int err = -1;

    if (cpn_channel_receive_protobuf(channel,
                &encryption_initiation_message__descriptor,
                (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Failed receiving negotiation response");
        goto out;
    }

    if (cpn_sign_pk_from_proto(remote_sign_key, msg->identity) < 0 ||
            cpn_asymmetric_pk_from_proto(remote_encrypt_key, msg->ephemeral) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Invalid keys");
        goto out;
    }

    err = 0;

out:
    if (msg)
        encryption_initiation_message__free_unpacked(msg, NULL);

    return err;
}

int receive_key_acknowledgement(struct cpn_asymmetric_pk *out,
        struct cpn_channel *c,
        const struct cpn_sign_pk *local_sign_pk,
        const struct cpn_asymmetric_pk *local_emph_key,
        const struct cpn_sign_pk *remote_sign_pk)
{
    EncryptionAcknowledgementMessage *msg = NULL;
    struct cpn_buf sign_buf = CPN_BUF_INIT;
    struct cpn_sign_pk msg_sign_pk;
    struct cpn_sign_sig sig;
    int err = -1;

    if (cpn_channel_receive_protobuf(c,
            &encryption_acknowledgement_message__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive acknowledge message");
        goto out;
    }

    if (cpn_sign_pk_from_proto(&msg_sign_pk, msg->identity) < 0 ||
            memcmp(&msg_sign_pk, remote_sign_pk, sizeof(msg_sign_pk))) {
        cpn_log(LOG_LEVEL_ERROR, "Verification key does not match");
        goto out;
    } else if (cpn_asymmetric_pk_from_proto(out, msg->ephemeral) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Ephemeral key does not match");
        goto out;
    } else if (cpn_sign_sig_from_proto(&sig, msg->signature) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Verification has invalid signature length");
        goto out;
    }

    cpn_buf_append_data(&sign_buf, remote_sign_pk->data, CPN_CRYPTO_SIGN_PKBYTES);
    cpn_buf_append_data(&sign_buf, out->data, CPN_CRYPTO_ASYMMETRIC_PKBYTES);
    cpn_buf_append_data(&sign_buf, local_emph_key->data, CPN_CRYPTO_ASYMMETRIC_PKBYTES);
    cpn_buf_append_data(&sign_buf, local_sign_pk->data, CPN_CRYPTO_ASYMMETRIC_PKBYTES);

    if (cpn_sign_sig_verify(remote_sign_pk, &sig, (uint8_t *) sign_buf.data, sign_buf.length) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to verify signature");
        goto out;
    }

    err = 0;

out:
    cpn_buf_clear(&sign_buf);
    if (msg)
        encryption_acknowledgement_message__free_unpacked(msg, NULL);

    return err;
}

int cpn_server_await_encryption(struct cpn_channel *channel,
        const struct cpn_sign_keys *sign_keys,
        struct cpn_sign_pk *remote_sign_key)
{
    struct cpn_asymmetric_keys emph_keys;
    struct cpn_asymmetric_pk remote_emph_key, received_emph_key;
    struct cpn_symmetric_key shared_key;

    if (receive_ephemeral_key(channel, remote_sign_key, &remote_emph_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive session key");
        return -1;
    }

    if (cpn_asymmetric_keys_generate(&emph_keys) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    if (send_key_acknowledgement(channel,
                sign_keys, &emph_keys.pk,
                remote_sign_key, &remote_emph_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send ephemeral key signature");
        return -1;
    }

    if (receive_key_acknowledgement(&received_emph_key,
                channel, &sign_keys->pk, &emph_keys.pk, remote_sign_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive verification");
        return -1;
    }

    if (memcmp(&received_emph_key, &remote_emph_key, sizeof(received_emph_key))) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid ephemeral key");
        return -1;
    }

    if (cpn_symmetric_key_from_scalarmult(&shared_key, &emph_keys, &remote_emph_key, false) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to derive shared secret");
        return -1;
    }

    cpn_memzero(&emph_keys, sizeof(emph_keys));

    if (cpn_channel_enable_encryption(channel, &shared_key, 1) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}
