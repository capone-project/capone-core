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

#include "capone/buf.h"
#include "capone/channel.h"
#include "capone/log.h"
#include "capone/session.h"
#include "capone/server.h"

#include "capone/proto/connect.pb-c.h"
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
        const struct cpn_sign_key_public *local_key)
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

    if (strcmp(msg->version, VERSION)) {
        cpn_log(LOG_LEVEL_ERROR, "Cannot handle announce message version %s",
                msg->version);
        goto out;
    }

    for (i = 0; i < msg->n_known_keys; i++) {
        if (msg->known_keys[i].len != sizeof(struct cpn_sign_key_public))
            continue;
        if (memcmp(msg->known_keys[i].data, local_key->data, sizeof(struct cpn_sign_key_public)))
            continue;
        cpn_log(LOG_LEVEL_DEBUG, "Skipping announce due to alreay being known");
        err = 0;
        goto out;
    }

    result.name = (char *) name;
    result.version = VERSION;
    cpn_sign_key_public_to_proto(&result.sign_key, local_key);

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
    if (result.sign_key)
        signature_key_message__free_unpacked(result.sign_key, NULL);

    return err;
}

int cpn_server_handle_session(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key,
        const struct cpn_service *service,
        const struct cpn_cfg *cfg)
{
    SessionInitiationMessage *initiation = NULL;
    SessionResult msg = SESSION_RESULT__INIT;
    struct cpn_session *session = NULL;
    struct cpn_cap *cap = NULL;
    int err;

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

    if (cpn_sessions_find((const struct cpn_session **) &session, initiation->identifier) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not find session for client");
        err = -1;
        goto out_notify;
    }

    if (cpn_caps_verify(cap, session->cap, remote_key, CPN_CAP_RIGHT_EXEC) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not authorize session initiation");
        err = -1;
        goto out_notify;
    }

    if ((err = cpn_sessions_remove(&session, initiation->identifier)) < 0) {
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

    if ((err = service->plugin->server_fn(channel, remote_key, session, cfg)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Service could not handle connection");
        goto out;
    }

out:
    if (initiation) {
        session_initiation_message__free_unpacked(initiation, NULL);
        cpn_session_free(session);
    }

    cpn_cap_free(cap);

    return 0;
}

int cpn_server_handle_query(struct cpn_channel *channel,
        const struct cpn_service *service)
{
    ServiceQueryResult results = SERVICE_QUERY_RESULT__INIT;
    ServiceQueryMessage *msg = NULL;
    int err = -1;

    if (cpn_channel_receive_protobuf(channel, &service_query_message__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Could not receive query");
        goto out;
    }

    if (strcmp(msg->version, VERSION)) {
        cpn_log(LOG_LEVEL_ERROR, "Cannot handle query message version %s",
                msg->version);
        goto out;
    }

    results.name = service->name;
    results.location = service->location;
    results.port = service->port;
    results.category = (char *) service->plugin->category;
    results.type = (char *) service->plugin->type;
    results.version = (char *) service->plugin->version;

    if (cpn_channel_write_protobuf(channel, (ProtobufCMessage *) &results) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send query results");
        goto out;
    }

    err = 0;

out:
    if (msg)
        service_query_message__free_unpacked(msg, NULL);

    return err;
}

static int create_cap(CapabilityMessage **out, const struct cpn_cap *root, uint32_t rights, const struct cpn_sign_key_public *key)
{
    CapabilityMessage *msg = NULL;
    struct cpn_cap *cap = NULL;
    int err = -1;

    if (cpn_cap_create_ref(&cap, root, rights, key) < 0)
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
        const struct cpn_sign_key_public *remote_key,
        const struct cpn_service_plugin *service)
{
    SessionRequestMessage *request = NULL;
    ProtobufCMessage *parameters = NULL;
    SessionRequestResult session_message = SESSION_REQUEST_RESULT__INIT;
    const struct cpn_session *session;
    int err = -1;

    if (cpn_channel_receive_protobuf(channel,
            &session_request_message__descriptor,
            (ProtobufCMessage **) &request) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive request");
        goto out;
    }

    if (service->params_desc) {
        if ((parameters = protobuf_c_message_unpack(service->params_desc, NULL,
                request->parameters.len, request->parameters.data)) == NULL)
            goto out;
    }

    if (cpn_sessions_add(&session, parameters, remote_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to add session");
        goto out;
    }

    session_message.identifier = session->identifier;

    if (create_cap(&session_message.cap, session->cap,
                CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM, remote_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to add invoker capability");
        goto out;
    }

    if (cpn_channel_write_protobuf(channel, &session_message.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send connection session");
        cpn_sessions_remove(NULL, session->identifier);
        goto out;
    }

    err = 0;

out:
    if (session_message.cap)
        capability_message__free_unpacked(session_message.cap, NULL);
    if (request)
        session_request_message__free_unpacked(request, NULL);

    return err;
}

int cpn_server_handle_termination(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key)
{
    SessionTerminationMessage *msg = NULL;
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

    /* If session could not be found we have nothing to do */
    if (cpn_sessions_find(&session, msg->identifier) < 0) {
        goto out;
    }

    if (cpn_cap_from_protobuf(&cap, msg->capability) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid capability");
        goto out;
    }

    if (cpn_caps_verify(cap, session->cap, remote_key, CPN_CAP_RIGHT_TERM) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Received unauthorized request");
        goto out;
    }

    if (cpn_sessions_remove(NULL, msg->identifier) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to terminate session");
        goto out;
    }

    err = 0;

out:
    if (msg)
        session_termination_message__free_unpacked(msg, NULL);
    cpn_cap_free(cap);

    return err;
}

static int send_signed_key(struct cpn_channel *channel,
        uint32_t id,
        const struct cpn_sign_key_pair *sign_keys,
        const struct cpn_encrypt_key_public *local_emph_key,
        const struct cpn_sign_key_public *remote_sign_key,
        const struct cpn_encrypt_key_public *remote_emph_key)
{
    ResponderKey msg = RESPONDER_KEY__INIT;
    uint8_t signature[crypto_sign_BYTES];
    struct cpn_buf sign_buf = CPN_BUF_INIT;
    int err = 0;

    cpn_buf_append_data(&sign_buf, sign_keys->pk.data, crypto_sign_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, (unsigned char *) &id, sizeof(id));
    cpn_buf_append_data(&sign_buf, local_emph_key->data, crypto_box_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, remote_emph_key->data, crypto_box_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, remote_sign_key->data, crypto_box_PUBLICKEYBYTES);

    memset(signature, 0, sizeof(signature));
    if ((err = crypto_sign_detached(signature, NULL,
                    (unsigned char *) sign_buf.data, sign_buf.length,
                    sign_keys->sk.data)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to sign ephemeral key");
        goto out;
    }

    msg.sessionid = id;
    msg.sign_pk.data = (uint8_t *) sign_keys->pk.data;
    msg.sign_pk.len = sizeof(sign_keys->pk.data);
    msg.ephm_pk.data = (uint8_t *) local_emph_key->data;
    msg.ephm_pk.len = sizeof(local_emph_key->data);
    msg.signature.data = signature;
    msg.signature.len = sizeof(signature);

    if ((err = cpn_channel_write_protobuf(channel, &msg.base)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid ephemeral key signature");
        goto out;
    }

out:
    cpn_buf_clear(&sign_buf);

    return 0;
}

static int receive_ephemeral_key(
        struct cpn_channel *channel,
        uint32_t *id,
        struct cpn_sign_key_public *remote_sign_key,
        struct cpn_encrypt_key_public *remote_encrypt_key)
{
    InitiatorKey *msg;

    if (cpn_channel_receive_protobuf(channel,
                &initiator_key__descriptor,
                (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Failed receiving negotiation response");
        return -1;
    }

    if (cpn_sign_key_public_from_bin(remote_sign_key,
                msg->sign_pk.data, msg->sign_pk.len) < 0 ||
            cpn_encrypt_key_public_from_bin(remote_encrypt_key,
                msg->ephm_pk.data, msg->ephm_pk.len) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Invalid keys");
        return -1;
    }

    *id = msg->sessionid;

    initiator_key__free_unpacked(msg, NULL);

    return 0;
}

static int receive_key_verification(struct cpn_channel *c,
        uint32_t id,
        const struct cpn_sign_key_public *local_pk,
        const struct cpn_encrypt_key_public *local_emph_key,
        const struct cpn_sign_key_public *remote_pk,
        const struct cpn_encrypt_key_public *remote_emph_key)
{
    AcknowledgeKey *msg = NULL;
    struct cpn_buf sign_buf = CPN_BUF_INIT;
    uint8_t *sign_data = NULL;
    int err = -1;

    if (cpn_channel_receive_protobuf(c,
            &acknowledge_key__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive acknowledge message");
        goto out;
    }

    if (msg->sessionid != id) {
        cpn_log(LOG_LEVEL_ERROR, "Verification has invalid session");
        goto out;
    } else if (msg->sign_pk.len != sizeof(remote_pk->data) ||
            memcmp(msg->sign_pk.data, remote_pk->data, msg->sign_pk.len)) {
        cpn_log(LOG_LEVEL_ERROR, "Verification key does not match");
        goto out;
    } else if (msg->signature.len != crypto_sign_BYTES) {
        cpn_log(LOG_LEVEL_ERROR, "Verification has invalid signature length");
        goto out;
    }

    cpn_buf_append_data(&sign_buf, remote_pk->data, crypto_sign_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, (unsigned char *) &id, sizeof(id));
    cpn_buf_append_data(&sign_buf, remote_emph_key->data, crypto_box_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, local_emph_key->data, crypto_box_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, local_pk->data, crypto_box_PUBLICKEYBYTES);

    if (crypto_sign_verify_detached(msg->signature.data,
                (unsigned char *) sign_buf.data, sign_buf.length,
                remote_pk->data) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid signature");
        goto out;
    }

    err = 0;

out:
    free(sign_data);
    cpn_buf_clear(&sign_buf);
    if (msg)
        acknowledge_key__free_unpacked(msg, NULL);

    return err;
}

int cpn_server_await_encryption(struct cpn_channel *channel,
        const struct cpn_sign_key_pair *sign_keys,
        struct cpn_sign_key_public *remote_sign_key)
{
    struct cpn_encrypt_key_pair emph_keys;
    struct cpn_encrypt_key_public remote_emph_key;
    struct cpn_symmetric_key shared_key;
    uint8_t scalarmult[crypto_scalarmult_BYTES];
    uint32_t id;
    crypto_generichash_state hash;

    if (receive_ephemeral_key(channel, &id, remote_sign_key, &remote_emph_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive session key");
        return -1;
    }

    if (cpn_encrypt_key_pair_generate(&emph_keys) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    if (send_signed_key(channel, id,
                sign_keys, &emph_keys.pk,
                remote_sign_key, &remote_emph_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send ephemeral key signature");
        return -1;
    }

    if (receive_key_verification(channel, id,
                &sign_keys->pk, &emph_keys.pk,
                remote_sign_key, &remote_emph_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive verification");
        return -1;
    }

    if (crypto_scalarmult(scalarmult, emph_keys.sk.data, remote_emph_key.data) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to perform scalarmultiplication");
        return -1;
    }

    if (crypto_generichash_init(&hash, NULL, 0, sizeof(shared_key.data)) < 0 ||
            crypto_generichash_update(&hash, scalarmult, sizeof(scalarmult)) < 0 ||
            crypto_generichash_update(&hash, remote_emph_key.data, sizeof(remote_emph_key.data)) < 0 ||
            crypto_generichash_update(&hash, emph_keys.pk.data, sizeof(emph_keys.pk.data)) < 0 ||
            crypto_generichash_final(&hash, shared_key.data, sizeof(shared_key.data)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to calculate h(q || pk1 || pk2)");
        return -1;
    }

    sodium_memzero(&emph_keys, sizeof(emph_keys));

    if (cpn_channel_enable_encryption(channel, &shared_key, 1) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}
