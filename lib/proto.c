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
#include "lib/keys.h"
#include "lib/log.h"

#include "proto/connect.pb-c.h"
#include "proto/encryption.pb-c.h"

#include "proto.h"

struct service_args {
    struct cfg *cfg;
    struct sd_service *service;
    struct sd_channel *channel;
    struct sd_service_session *session;
};

static int send_session_key(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_encrypt_key_public *encrypt_key);
static int receive_session_key(struct sd_channel *channel,
        struct sd_sign_key_public *remote_sign_key,
        struct sd_encrypt_key_public *remote_encrypt_key);
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

static int send_key_signature(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_symmetric_key *ephemeral_key)
{
    uint8_t signature[crypto_sign_BYTES];
    EphemeralKeySignatureMessage msg = EPHEMERAL_KEY_SIGNATURE_MESSAGE__INIT;

    if (crypto_sign_detached(signature, NULL,
            ephemeral_key->data, sizeof(ephemeral_key->data),
            sign_keys->sk.data) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to sign ephemeral key");
        return -1;
    }

    msg.signature.data = signature;
    msg.signature.len = sizeof(signature);

    if (sd_channel_write_protobuf(channel, &msg.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Received invalid ephemeral key signature");
        return -1;
    }

    return 0;
}

static int receive_key_signature(struct sd_channel *channel,
        const struct sd_sign_key_public *verify_key,
        const struct sd_symmetric_key *ephemeral_key)
{
    EphemeralKeySignatureMessage *msg = NULL;

    if (sd_channel_receive_protobuf(channel,
            &ephemeral_key_signature_message__descriptor,
            (ProtobufCMessage **) &msg) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        goto out_err;
    }

    if (msg->signature.len != crypto_sign_BYTES) {
        sd_log(LOG_LEVEL_ERROR, "Received signature's length does not match");
        goto out_err;
    }

    if (crypto_sign_verify_detached(msg->signature.data, ephemeral_key->data,
                sizeof(ephemeral_key->data), verify_key->data) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Ephemeral key signature is invalid");
        goto out_err;
    }

    return 0;

out_err:
    ephemeral_key_signature_message__free_unpacked(msg, NULL);
    return -1;
}

int sd_proto_initiate_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_sign_key_public *remote_sign_key)
{
    struct sd_encrypt_key_pair local_keys;
    struct sd_encrypt_key_public received_encrypt_key;
    struct sd_sign_key_public received_sign_key;
    struct sd_symmetric_key shared_key;
    uint8_t scalarmult[crypto_scalarmult_BYTES];
    crypto_generichash_state hash;

    if (sd_encrypt_key_pair_generate(&local_keys) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    if (send_session_key(channel, sign_keys, &local_keys.pk) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send session key");
        return -1;
    }

    if (receive_session_key(channel, &received_sign_key, &received_encrypt_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive session key");
        return -1;
    }

    if (memcmp(received_sign_key.data, remote_sign_key->data, sizeof(received_sign_key.data))) {
        sd_log(LOG_LEVEL_ERROR, "Signature key does not match expected key");
        return -1;
    }

    if (crypto_scalarmult(scalarmult, local_keys.sk.data, received_encrypt_key.data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to perform scalarmultiplication");
        return -1;
    }

    if (crypto_generichash_init(&hash, NULL, 0, sizeof(shared_key.data)) < 0 ||
            crypto_generichash_update(&hash, scalarmult, sizeof(scalarmult)) < 0 ||
            crypto_generichash_update(&hash, local_keys.pk.data, sizeof(local_keys.pk.data)) < 0 ||
            crypto_generichash_update(&hash, received_encrypt_key.data, sizeof(received_encrypt_key.data)) < 0 ||
            crypto_generichash_final(&hash, shared_key.data, sizeof(shared_key.data)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to calculate h(q || pk1 || pk2)");
        return -1;
    }

    sodium_memzero(&local_keys, sizeof(local_keys));

    if (send_key_signature(channel, sign_keys, &shared_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send ephemeral key signature");
        return -1;
    }

    if (receive_key_signature(channel, remote_sign_key, &shared_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        return -1;
    }

    if (sd_channel_enable_encryption(channel, &shared_key, 0) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

    return 0;
}

int sd_proto_initiate_session(struct sd_channel *channel, const char *sessionkey, int sessionid)
{
    SessionInitiationMessage initiation = SESSION_INITIATION_MESSAGE__INIT;
    struct sd_symmetric_key key;

    initiation.sessionid = sessionid;
    if (sd_channel_write_protobuf(channel, &initiation.base) < 0 ) {
        sd_log(LOG_LEVEL_ERROR, "Could not initiate session");
        return -1;
    }

    if (sd_symmetric_key_from_hex(&key, sessionkey) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not retrieve symmetric key");
        return -1;
    }

    if (sd_channel_enable_encryption(channel, &key, 0) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not enable symmetric encryption");
        return -1;
    }

    return 0;
}

int sd_proto_handle_session(struct sd_channel *channel,
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
        if (session->sessionid == initiation->sessionid)
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

    if (sd_channel_enable_encryption(channel, &session->session_key, 1) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not enable symmetric encryption");
        return -1;
    }

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
        const struct sd_service_parameter *params, size_t nparams)
{
    SessionRequestMessage request = SESSION_REQUEST_MESSAGE__INIT;
    SessionMessage *session;
    size_t i;

    memset(out, 0, sizeof(struct sd_service_session));

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
    assert(session->sessionkey.len == crypto_secretbox_KEYBYTES);

    out->sessionid = session->sessionid;
    memcpy(&out->session_key, session->sessionkey.data, session->sessionkey.len);

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

int sd_proto_await_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        struct sd_sign_key_public *remote_sign_key)
{
    struct sd_encrypt_key_pair local_keys;
    struct sd_encrypt_key_public remote_key;
    struct sd_symmetric_key shared_key;
    uint8_t scalarmult[crypto_scalarmult_BYTES];
    crypto_generichash_state hash;

    if (sd_encrypt_key_pair_generate(&local_keys) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to generate key pair");
        return -1;
    }

    if (receive_session_key(channel, remote_sign_key, &remote_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive session key");
        return -1;
    }

    if (send_session_key(channel, sign_keys, &local_keys.pk) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send session key");
        return -1;
    }

    if (crypto_scalarmult(scalarmult, local_keys.sk.data, remote_key.data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to perform scalarmultiplication");
        return -1;
    }

    if (crypto_generichash_init(&hash, NULL, 0, sizeof(shared_key.data)) < 0 ||
            crypto_generichash_update(&hash, scalarmult, sizeof(scalarmult)) < 0 ||
            crypto_generichash_update(&hash, remote_key.data, sizeof(remote_key.data)) < 0 ||
            crypto_generichash_update(&hash, local_keys.pk.data, sizeof(local_keys.pk.data)) < 0 ||
            crypto_generichash_final(&hash, shared_key.data, sizeof(shared_key.data)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to calculate h(q || pk1 || pk2)");
        return -1;
    }

    sodium_memzero(&local_keys, sizeof(local_keys));

    if (send_key_signature(channel, sign_keys, &shared_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send ephemeral key signature");
        return -1;
    }

    if (receive_key_signature(channel, remote_sign_key, &shared_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive ephemeral key signature");
        return -1;
    }

    if (sd_channel_enable_encryption(channel, &shared_key, 1) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not enable encryption");
        return -1;
    }

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
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist)
{
    SessionRequestMessage *request;
    SessionMessage session_message = SESSION_MESSAGE__INIT;
    struct sd_sign_key_public remote_sign_key;
    struct sd_symmetric_key session_key;
    struct sd_service_parameter *params;
    struct sd_service_session *session;

    if (!is_whitelisted(&remote_sign_key, whitelist, nwhitelist)) {
        sd_log(LOG_LEVEL_ERROR, "Received connection from unknown signature key");
        return -1;
    }

    if (sd_channel_receive_protobuf(channel,
            &session_request_message__descriptor,
            (ProtobufCMessage **) &request) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive request");
        return -1;
    }

    if (sd_symmetric_key_generate(&session_key) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to generate sesson session_key");
        return -1;
    }

    session_message.sessionkey.data = session_key.data;
    session_message.sessionkey.len = sizeof(session_key.data);
    session_message.sessionid = randombytes_random();

    if (sd_channel_write_protobuf(channel, &session_message.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send connection session");
        return -1;
    }

    if (convert_params(&params, request) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to convert parameters");
        return -1;
    }
    session_request_message__free_unpacked(request, NULL);

    session = malloc(sizeof(struct sd_service_session));
    session->sessionid = session_message.sessionid;
    session->parameters = params;
    session->nparameters = request->n_parameters;
    memcpy(session->session_key.data, session_key.data, sizeof(session_key.data));
    memcpy(session->identity.data, remote_sign_key.data, sizeof(session->identity.data));
    session->next = NULL;

    *out = session;

    return 0;
}

static int send_session_key(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_encrypt_key_public *encrypt_key)
{
    uint8_t signature[crypto_sign_BYTES];
    SessionKeyMessage env = SESSION_KEY_MESSAGE__INIT;

    /* We may end up sending more bytes than the signature is
     * long. To avoid a buffer overflow on the other side, always
     * send the maximum signature length and set the trailing
     * bytes to zero*/
    memset(signature, 0, sizeof(signature));
    if (crypto_sign_detached(signature, NULL,
                encrypt_key->data, sizeof(encrypt_key->data), sign_keys->sk.data) != 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to sign generated key");
        return -1;
    }

    env.sign_pk.data = (uint8_t *) sign_keys->pk.data;
    env.sign_pk.len = sizeof(sign_keys->pk.data);
    env.encrypt_pk.data = (uint8_t *) encrypt_key->data;
    env.encrypt_pk.len = sizeof(encrypt_key->data);
    env.signature.data = signature;
    env.signature.len = sizeof(signature);

    if (sd_channel_write_protobuf(channel, &env.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not send negotiation");
        return -1;
    }

    return 0;
}

static int receive_session_key(struct sd_channel *channel,
        struct sd_sign_key_public *remote_sign_key,
        struct sd_encrypt_key_public *remote_encrypt_key)
{
    SessionKeyMessage *response;

    if (sd_channel_receive_protobuf(channel,
                &session_key_message__descriptor, (ProtobufCMessage **) &response) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Failed receiving negotiation response");
        return -1;
    }

    if (response->sign_pk.len != crypto_sign_PUBLICKEYBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Received signing key length does not match");
        return -1;
    }

    if (crypto_sign_verify_detached(response->signature.data,
                response->encrypt_pk.data, response->encrypt_pk.len, response->sign_pk.data) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Received key not signed correctly");
        return -1;
    }

    if (remote_sign_key) {
        memcpy(remote_sign_key->data, response->sign_pk.data, sizeof(remote_sign_key->data));
    }

    if (sd_encrypt_key_public_from_bin(remote_encrypt_key,
                response->encrypt_pk.data, response->encrypt_pk.len) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not retrieve remote public key");
        return -1;
    }

    session_key_message__free_unpacked(response, NULL);

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
