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
#include "capone/log.h"
#include "capone/proto.h"

#include "capone/proto/connect.pb-c.h"
#include "capone/proto/encryption.pb-c.h"

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

static int send_ephemeral_key(struct cpn_channel *channel,
        uint32_t id,
        const struct cpn_sign_key_pair *sign_keys,
        const struct cpn_encrypt_key_public *encrypt_key)
{
    InitiatorKey msg = INITIATOR_KEY__INIT;

    msg.sign_pk.data = (uint8_t *) sign_keys->pk.data;
    msg.sign_pk.len = sizeof(sign_keys->pk.data);
    msg.ephm_pk.data = (uint8_t *) encrypt_key->data;
    msg.ephm_pk.len = sizeof(encrypt_key->data);
    msg.sessionid = id;

    if (cpn_channel_write_protobuf(channel, &msg.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not send negotiation");
        return -1;
    }

    return 0;
}

static int receive_signed_key(struct cpn_encrypt_key_public *out,
        struct cpn_channel *channel,
        uint32_t id,
        const struct cpn_sign_key_public *local_sign_key,
        const struct cpn_encrypt_key_public *local_emph_key,
        const struct cpn_sign_key_public *remote_sign_key)
{
    ResponderKey *msg;
    struct cpn_buf sign_buf = CPN_BUF_INIT;
    struct cpn_sign_key_public msg_sign_key;
    struct cpn_encrypt_key_public msg_emph_key;
    int ret = -1;

    if (cpn_channel_receive_protobuf(channel,
            &responder_key__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        goto out;
    }

    /* Verify parameters */
    if (msg->sessionid != id) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid session id");
        goto out;
    } else if (msg->signature.len != crypto_sign_BYTES) {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid signature");
        goto out;
    } else if (cpn_sign_key_public_from_bin(&msg_sign_key, msg->sign_pk.data, msg->sign_pk.len) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Initiator's long-term signature key is invalid");
        goto out;
    } else if (cpn_encrypt_key_public_from_bin(&msg_emph_key, msg->ephm_pk.data, msg->ephm_pk.len) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Initiator's ephemeral key is invalid");
        goto out;
    }

    if (memcmp(&msg_sign_key, remote_sign_key, sizeof(msg_sign_key))) {
        cpn_log(LOG_LEVEL_ERROR, "Received unexpected sign key");
        goto out;
    }

    cpn_buf_append_data(&sign_buf, msg_sign_key.data, crypto_sign_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, (unsigned char *) &id, sizeof(id));
    cpn_buf_append_data(&sign_buf, msg_emph_key.data, crypto_box_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, local_emph_key->data, crypto_box_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, local_sign_key->data, crypto_box_PUBLICKEYBYTES);

    if (crypto_sign_verify_detached(msg->signature.data,
                (unsigned char *) sign_buf.data, sign_buf.length,
                remote_sign_key->data) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Received invalid signature");
        goto out;
    }

    if (out) {
        memcpy(out, &msg_emph_key, sizeof(msg_emph_key));
    }

    ret = 0;

out:
    cpn_buf_clear(&sign_buf);
    if (msg)
        responder_key__free_unpacked(msg, NULL);

    return ret;
}

static int send_key_verification(struct cpn_channel *c,
        uint32_t id,
        const struct cpn_sign_key_pair *sign_keys,
        const struct cpn_encrypt_key_public *local_emph_key,
        const struct cpn_sign_key_public *remote_pk,
        const struct cpn_encrypt_key_public *remote_emph_pk)
{
    AcknowledgeKey msg = ACKNOWLEDGE_KEY__INIT;
    struct cpn_buf sign_buf = CPN_BUF_INIT;
    uint8_t signature[crypto_sign_BYTES], *sign_data = NULL;
    int err = 0;

    cpn_buf_append_data(&sign_buf, sign_keys->pk.data, crypto_sign_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, (unsigned char *) &id, sizeof(id));
    cpn_buf_append_data(&sign_buf, local_emph_key->data, crypto_box_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, remote_emph_pk->data, crypto_box_PUBLICKEYBYTES);
    cpn_buf_append_data(&sign_buf, remote_pk->data, crypto_box_PUBLICKEYBYTES);

    memset(signature, 0, sizeof(signature));
    if ((err = crypto_sign_detached(signature, NULL,
                    (unsigned char *) sign_buf.data, sign_buf.length,
                    sign_keys->sk.data)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to sign key verification");
        goto out;
    }

    msg.sessionid = id;
    msg.sign_pk.data = (uint8_t *) sign_keys->pk.data;
    msg.sign_pk.len = sizeof(sign_keys->pk.data);
    msg.signature.data = signature;
    msg.signature.len = sizeof(signature);

    if (cpn_channel_write_protobuf(c, &msg.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send verification message");
        return -1;
    }

out:
    free(sign_data);

    return err;
}

int cpn_proto_initiate_encryption(struct cpn_channel *channel,
        const struct cpn_sign_key_pair *sign_keys,
        const struct cpn_sign_key_public *remote_sign_key)
{
    struct cpn_encrypt_key_pair emph_keys;
    struct cpn_encrypt_key_public remote_emph_key;
    struct cpn_symmetric_key shared_key;
    uint8_t scalarmult[crypto_scalarmult_BYTES];
    crypto_generichash_state hash;
    uint32_t id;

    if (cpn_encrypt_key_pair_generate(&emph_keys) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    id = randombytes_random();

    if (send_ephemeral_key(channel, id, sign_keys, &emph_keys.pk) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send session key");
        return -1;
    }

    if (receive_signed_key(&remote_emph_key, channel, id,
                &sign_keys->pk, &emph_keys.pk, remote_sign_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        return -1;
    }

    if (send_key_verification(channel, id,
                sign_keys, &emph_keys.pk,
                remote_sign_key, &remote_emph_key) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send key verification");
        return -1;
    }

    if (crypto_scalarmult(scalarmult, emph_keys.sk.data, remote_emph_key.data) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to perform scalarmultiplication");
        return -1;
    }

    if (crypto_generichash_init(&hash, NULL, 0, sizeof(shared_key.data)) < 0 ||
            crypto_generichash_update(&hash, scalarmult, sizeof(scalarmult)) < 0 ||
            crypto_generichash_update(&hash, emph_keys.pk.data, sizeof(emph_keys.pk.data)) < 0 ||
            crypto_generichash_update(&hash, remote_emph_key.data, sizeof(remote_emph_key.data)) < 0 ||
            crypto_generichash_final(&hash, shared_key.data, sizeof(shared_key.data)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to calculate h(q || pk1 || pk2)");
        return -1;
    }

    sodium_memzero(&emph_keys, sizeof(emph_keys));

    if (cpn_channel_enable_encryption(channel, &shared_key, 0) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}
