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

#include <pthread.h>

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
static struct registrant {
    struct sd_sign_key_public identity;
    struct sd_channel channel;
} registrants[MAX_REGISTRANTS];
static int nregistrants;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct sd_service_parameter **out)
{
    static const struct sd_service_parameter params[] = {
        { "mode", "register" },
        { "mode", "request" },
        { "invoker", NULL },
        { "requested-identity", NULL },
        { "service-identity", NULL },
        { "service-address", NULL },
        { "service-port", NULL },
        { "service-parameters", NULL },
    };

    *out = params;
    return ARRAY_SIZE(params);
}

static int relay_capability_request(struct sd_channel *channel,
        const CapabilityRequest *request,
        const struct sd_cfg *cfg)
{
    Capability cap = CAPABILITY__INIT;
    char *host = NULL, *port = NULL;
    struct sd_channel service_channel;
    struct sd_sign_key_pair local_keys;
    struct sd_sign_key_public service_key, invoker_key;
    struct sd_session session;
    struct sd_service_parameter *params = NULL;
    size_t i;
    int ret = 0;

    memset(&service_channel, 0, sizeof(struct sd_channel));

    if ((ret = sd_sign_key_pair_from_config(&local_keys, cfg)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to retrieve local key pair from config");
        goto out;
    }

    sd_sign_key_public_from_bin(&service_key,
            request->service_identity.data, request->service_identity.len);
    sd_sign_key_public_from_bin(&invoker_key,
            request->invoker_identity.data, request->invoker_identity.len);

    if (request->n_parameters) {
        params = malloc(sizeof(struct sd_service_parameter) * request->n_parameters);
        for (i = 0; i < request->n_parameters; i++) {
            params[i].key = request->parameters[i]->key;
            params[i].value = (const char *) &request->parameters[i]->value;
        }
    }

    if ((ret = sd_proto_initiate_connection(&service_channel,
                    request->service_address, request->service_port,
                    &local_keys, &service_key, SD_CONNECTION_TYPE_REQUEST)) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to initiate connection type to remote service");
        goto out;
    }

    if ((ret = sd_proto_send_request(&cap.sessionid, &service_channel, &invoker_key,
                    params, request->n_parameters)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to send request to remote service");
        goto out;
    }

    cap.sessionid = session.sessionid;
    cap.identity.data = invoker_key.data;
    cap.identity.len = sizeof(invoker_key.data);
    cap.service.data = service_key.data;
    cap.service.len = sizeof(service_key.data);

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
    struct sd_sign_key_hex requester, invoker, service;
    struct sd_cfg cfg;
    size_t i;

    if (argc != 1) {
        puts("USAGE: register <CONFIG>");
        return -1;
    }

    if (sd_cfg_parse(&cfg, argv[0]) < 0) {
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

        if (sd_sign_key_hex_from_bin(&requester,
                    request->requester_identity.data, request->requester_identity.len) < 0 ||
                sd_sign_key_hex_from_bin(&invoker,
                    request->invoker_identity.data, request->invoker_identity.len) < 0 ||
                sd_sign_key_hex_from_bin(&service,
                    request->service_identity.data, request->service_identity.len) < 0)
        {
            sd_log(LOG_LEVEL_ERROR, "Unable to parse remote keys");
            return -1;
        }

        printf("request from: %s\n"
               "     invoker: %s\n"
               "     service: %s\n"
               "     address: %s\n"
               "        port: %s\n",
               requester.data, invoker.data, service.data,
               request->service_address, request->service_port);
        for (i = 0; i < request->n_parameters; i++) {
            CapabilityRequest__Parameter *param = request->parameters[i];

            printf("        param: %s=%s\n", param->key, param->value);
        }

        while (true) {
            int c;

            printf("Accept? [y/n] ");

            c = getchar();

            if (c == 'y') {
                if (relay_capability_request(channel, request, &cfg) < 0)
                    sd_log(LOG_LEVEL_ERROR, "Unable to relay capability");
                else
                    printf("Accepted capability request from %s\n", requester.data);

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

    if (sd_channel_receive_protobuf(channel, &capability__descriptor,
                (ProtobufCMessage **) &capability) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to receive capability");
        return -1;
    }

    if (sd_sign_key_hex_from_bin(&identity_hex,
                capability->identity.data, capability->identity.len) < 0 ||
            sd_sign_key_hex_from_bin(&service_hex,
                capability->service.data, capability->service.len) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to parse capability keys");
        return -1;
    }

    printf("identity:   %s\n"
           "service:    %s\n"
           "sessionid:  %"PRIu32"\n",
           identity_hex.data, service_hex.data, capability->sessionid);

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
        const struct sd_session *session)
{
    int n;

    pthread_mutex_lock(&mutex);

    n = nregistrants++;

    memcpy(&registrants[n].channel, channel, sizeof(struct sd_channel));
    memcpy(&registrants[n].identity, &session->invoker, sizeof(session->invoker));

    sd_log(LOG_LEVEL_VERBOSE, "%d identities registered", n + 1);

    pthread_mutex_unlock(&mutex);

    channel->fd = -1;

    return 0;
}

static int handle_request(struct sd_channel *channel,
        const struct sd_session *session)
{
    CapabilityRequest request = CAPABILITY_REQUEST__INIT;
    Capability *capability;

    const char *invoker_identity_hex, *service_identity_hex,
          *requested_identity_hex, *address, *port;
    struct sd_sign_key_public invoker_identity, service_identity,
                              requested_identity;
    struct registrant *registrant = NULL;
    int i, n;

    if (sd_service_parameters_get_value(&invoker_identity_hex, "invoker",
                session->parameters, session->nparameters) ||
            sd_sign_key_public_from_hex(&invoker_identity, invoker_identity_hex))
    {
        sd_log(LOG_LEVEL_ERROR, "Invalid for-identity specified in capability request");
        return -1;
    }

    if (sd_service_parameters_get_value(&requested_identity_hex, "requested-identity",
                session->parameters, session->nparameters) ||
            sd_sign_key_public_from_hex(&requested_identity, requested_identity_hex))
    {
        sd_log(LOG_LEVEL_ERROR, "Invalid requested identity specified in capability request");
        return -1;
    }

    if (sd_service_parameters_get_value(&service_identity_hex, "service-identity",
                session->parameters, session->nparameters) ||
            sd_sign_key_public_from_hex(&service_identity, service_identity_hex))
    {
        sd_log(LOG_LEVEL_ERROR, "Invalid service-identity specified in capability request");
        return -1;
    }

    if (sd_service_parameters_get_value(&address, "service-address",
                session->parameters, session->nparameters) ||
            sd_service_parameters_get_value(&port, "service-port",
                session->parameters, session->nparameters))
    {
        sd_log(LOG_LEVEL_ERROR, "Service address not specified in capability request");
        return -1;
    }

    /* TODO: handle parameters */

    pthread_mutex_lock(&mutex);
    n = nregistrants;

    for (i = 0; i < n; i++) {
        if (sd_channel_is_closed(&registrants[i].channel)) {
            memmove(&registrants[i], &registrants[i + 1], (n - i - 1) * sizeof(struct registrant));
            i--;
            n--;
            nregistrants--;
            sd_log(LOG_LEVEL_ERROR, "Removed identiy");
        }
    }

    for (i = 0; i < n; i++) {
        if (!memcmp(registrants[i].identity.data, requested_identity.data, sizeof(requested_identity.data))) {
            registrant = &registrants[i];
            break;
        }
    }
    pthread_mutex_unlock(&mutex);

    if (registrant == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Identity specified in capability request is not registered");
        return -1;
    }

    request.requester_identity.data = (uint8_t *) session->invoker.data;
    request.requester_identity.len = sizeof(session->invoker.data);
    request.invoker_identity.data = (uint8_t *) invoker_identity.data;
    request.invoker_identity.len = sizeof(invoker_identity.data);

    request.service_identity.data = (uint8_t *) service_identity.data;
    request.service_identity.len = sizeof(service_identity.data);
    request.service_address = (char *) address;
    request.service_port = (char *) port;

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
        const struct sd_session *session,
        const struct sd_cfg *cfg)
{
    const char *mode;

    UNUSED(cfg);

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
    memset(&registrants, 0, sizeof(registrants));

    service->category = "Capabilities";
    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}
