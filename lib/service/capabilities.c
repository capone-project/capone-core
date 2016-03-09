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

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

#include "proto/capabilities.pb-c.h"

#include "lib/cfg.h"
#include "lib/channel.h"
#include "lib/common.h"
#include "lib/keys.h"
#include "lib/proto.h"
#include "lib/service.h"
#include "lib/log.h"

#define MAX_REGISTRANTS 1024

static struct {
    struct registrant {
        struct sd_sign_key_public identity;
        struct sd_channel channel;
    } registrants[MAX_REGISTRANTS];
    int nregistrants;
} *registrants;

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct sd_service_parameter **out)
{
    static const char *types[] = { "register", "request" };
    static const struct sd_service_parameter params[] = {
        { "type", ARRAY_SIZE(types), types },
        { "request-for-identity", 0, NULL },
        { "request-for-service", 0, NULL },
        { "request-parameters", 0, NULL },
    };

    *out = params;
    return ARRAY_SIZE(params);
}

static int request_capability(struct sd_channel *channel, const CapabilityRequest *request, const struct cfg *cfg)
{
    Capability cap = CAPABILITY__INIT;
    char *host = NULL, *port = NULL;
    struct sd_sign_key_hex service_hex;
    struct sd_channel service_channel;
    struct sd_sign_key_pair local_keys;
    struct sd_sign_key_public remote_key;
    struct sd_service_session session;
    struct sd_service_parameter *params = NULL;
    size_t i;
    int ret = 0;

    if (request->n_parameters) {
        params = malloc(sizeof(struct sd_service_parameter) * request->n_parameters);
        for (i = 0; i < request->n_parameters; i++) {
            params[i].key = request->parameters[i]->key;
            params[i].values = (const char **) &request->parameters[i]->value;
            params[i].nvalues = 1;
        }
    }

    if (sd_sign_key_hex_from_bin(&service_hex, request->service.data, request->service.len) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Invalid service key length");
        ret = -1;
        goto out;
    }

    if ((host = cfg_get_str_value(cfg, service_hex.data, "address")) == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Unable to parse address for remote service");
        ret = -1;
        goto out;
    }
    if ((port = cfg_get_str_value(cfg, service_hex.data, "port")) == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Unable to parse port for remote service");
        ret = -1;
        goto out;
    }

    if ((ret = sd_sign_key_pair_from_config(&local_keys, cfg)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to retrieve local key pair from config");
        goto out;
    }
    if ((ret = sd_sign_key_public_from_bin(&remote_key, request->service.data, request->service.len)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to parse public key from remote service");
        goto out;
    }

    if ((ret = sd_proto_initiate_connection_type(&service_channel, host, port, SD_CONNECTION_TYPE_REQUEST)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to initiate connection type to remote service");
        goto out;
    }
    if ((ret = sd_proto_initiate_encryption(&service_channel, &local_keys, &remote_key)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to initiate encryption with remote service");
        goto out;
    }
    if ((ret = sd_proto_send_request(&session, &service_channel, params, request->n_parameters)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send request to remote service");
        goto out;
    }

    cap.sessionid = session.sessionid;
    cap.sessionkey.data = session.session_key.data;
    cap.sessionkey.len = sizeof(session.session_key.data);
    cap.identity.data = local_keys.pk.data;
    cap.identity.len = sizeof(local_keys.pk.data);
    cap.service.data = remote_key.data;
    cap.service.len = sizeof(remote_key.data);
    if ((ret = sd_channel_write_protobuf(channel, &cap.base)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send requested capability");
        goto out;
    }

out:
    sd_channel_close(&service_channel);

    free(params);
    free(host);
    free(port);

    return ret;
}

static int invoke_register(struct sd_channel *channel, int argc, char **argv)
{
    CapabilityRequest *request;
    struct sd_sign_key_hex identity, service;
    struct cfg cfg;
    size_t i;

    if (argc != 1) {
        puts("USAGE: register <CONFIG>");
        return -1;
    }

    if (cfg_parse(&cfg, argv[0]) < 0) {
        puts("Could not find config");
        return -1;
    }

    while (true) {
        if (sd_channel_receive_protobuf(channel, &capability_request__descriptor,
                (ProtobufCMessage **) &request) < 0)
        {
            sd_log(LOG_LEVEL_ERROR, "Error receiving registered capability requests");
            return -1;
        }

        if (sd_sign_key_hex_from_bin(&identity,
                    request->requester.data, request->requester.len) < 0 ||
                sd_sign_key_hex_from_bin(&service,
                    request->service.data, request->service.len) < 0)
        {
            sd_log(LOG_LEVEL_ERROR, "Unable to parse remote keys");
            return -1;
        }

        printf("request from %s\n        service: %s\n", identity.data, service.data);
        for (i = 0; i < request->n_parameters; i++) {
            CapabilityRequest__Parameter *param = request->parameters[i];

            printf("        param: %s=%s\n", param->key, param->value);
        }

        printf("Accept? [y/n] ");
        while (true) {
            int c = getchar();

            if (c == 'y') {
                if (request_capability(channel, request, &cfg) < 0)
                    sd_log(LOG_LEVEL_ERROR, "Unable to relay capability");
                else
                    printf("Accepted capability request from %s\n", identity.data);

                break;
            } else if (c == 'n') {
                break;
            }
        }

        capability_request__free_unpacked(request, NULL);
    }

    return 0;
}

static int invoke_request(struct sd_channel *channel)
{
    Capability *capability;
    struct sd_sign_key_hex identity_hex, service_hex;
    struct sd_symmetric_key_hex session_hex;

    if (sd_channel_receive_protobuf(channel, &capability__descriptor,
                (ProtobufCMessage **) &capability) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive capability");
        return -1;
    }

    if (sd_sign_key_hex_from_bin(&identity_hex,
                capability->identity.data, capability->identity.len) < 0 ||
            sd_sign_key_hex_from_bin(&service_hex,
                capability->service.data, capability->service.len) < 0 ||
            sd_symmetric_key_hex_from_bin(&session_hex,
                capability->sessionkey.data, capability->sessionkey.len) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to parse capability keys");
        return -1;
    }

    printf("identity:   %s\n"
           "service:    %s\n"
           "sessionid:  %"PRIu32"\n"
           "sessionkey: %s\n",
           identity_hex.data, service_hex.data, capability->sessionid, session_hex.data);

    capability__free_unpacked(capability, NULL);

    return 0;
}

static int invoke(struct sd_channel *channel, int argc, char **argv)
{
    if (argc < 1) {
        puts("USAGE: capabilities (register|request)");
        return -1;
    }

    if (!strcmp(argv[0], "register"))
        return invoke_register(channel, argc - 1, argv + 1);
    else if (!strcmp(argv[0], "request"))
        return invoke_request(channel);
    else {
        sd_log(LOG_LEVEL_ERROR, "Unknown parameter '%s'", argv[0]);
        return -1;
    }
}

static int handle_register(struct sd_channel *channel,
        const struct sd_service_session *session)
{
    int n = registrants->nregistrants;

    registrants->nregistrants++;
    memcpy(&registrants->registrants[n].channel, channel, sizeof(struct sd_channel));
    memcpy(&registrants->registrants[n].identity, &session->identity, sizeof(session->identity));

    sd_log(LOG_LEVEL_VERBOSE, "%d identities registered", n + 1);

    return 0;
}

static int handle_request(struct sd_channel *channel,
        const struct sd_service_session *session)
{
    CapabilityRequest request = CAPABILITY_REQUEST__INIT;
    Capability *capability;

    const char *remote_entity_hex, *remote_service_hex;
    struct sd_sign_key_public remote_identity, remote_service;
    struct registrant *registrant;
    int i;

    sd_service_parameters_get_value(&remote_entity_hex, "request-for-identity", session->parameters, session->nparameters);
    if (sd_sign_key_public_from_hex(&remote_identity, remote_entity_hex)) {
        sd_log(LOG_LEVEL_ERROR, "Invalid remote identity specified in capability request");
        return -1;
    }

    sd_service_parameters_get_value(&remote_service_hex, "request-for-service", session->parameters, session->nparameters);
    if (sd_sign_key_public_from_hex(&remote_service, remote_service_hex)) {
        sd_log(LOG_LEVEL_ERROR, "Invalid service identity specified in capability request");
        return -1;
    }

    for (i = 0; i < registrants->nregistrants; i++) {
        if (!memcmp(registrants->registrants[i].identity.data, remote_identity.data, sizeof(remote_identity.data))) {
            registrant = &registrants->registrants[i];
            break;
        }
    }

    if (registrant == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Identity specified in capability request is not registered");
        return -1;
    }

    request.identity.data = (uint8_t *) remote_identity.data;
    request.identity.len = sizeof(remote_identity.data);
    request.service.data = (uint8_t *) remote_service.data;
    request.service.len = sizeof(remote_service.data);
    request.requester.data = (uint8_t *) session->identity.data;
    request.requester.len = sizeof(session->identity.data);
    /* TODO: parameters */

    if (sd_channel_write_protobuf(&registrant->channel, &request.base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to request capability request");
        return -1;
    }

    if (sd_channel_receive_protobuf(&registrant->channel,
                &capability__descriptor, (ProtobufCMessage **) &capability) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive capability");
        return -1;
    }

    if (sd_channel_write_protobuf(channel, &capability->base) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to request capability");
        return -1;
    }

    return 0;
}

static int handle(struct sd_channel *channel,
        const struct sd_service_session *session)
{
    const char *mode;

    if (sd_service_parameters_get_value(&mode, "mode",
                session->parameters, session->nparameters) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Required parameter 'mode' not set");
        return -1;
    }

    if (!strcmp(mode, "register")) {
        return handle_register(channel, session);
    } else if (!strcmp(mode, "request")) {
        return handle_request(channel, session);
    } else {
        sd_log(LOG_LEVEL_ERROR, "Unable to handle connection mode '%s'", mode);
        return -1;
    }

    return 0;
}

int sd_capabilities_init_service(struct sd_service *service)
{
    int shmid;

    shmid = shmget(IPC_PRIVATE, sizeof(*registrants), IPC_CREAT | IPC_EXCL | 0600);
    if (shmid == -1) {
        sd_log(LOG_LEVEL_ERROR, "Unable to map registrant count");
        return -1;
    }
    registrants = shmat(shmid, NULL, 0);
    memset(registrants, 0, sizeof(*registrants));

    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}
