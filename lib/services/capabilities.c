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

#include <sys/select.h>

#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

#include "capone/cfg.h"
#include "capone/channel.h"
#include "capone/common.h"
#include "capone/keys.h"
#include "capone/proto.h"
#include "capone/service.h"
#include "capone/list.h"
#include "capone/log.h"
#include "capone/opts.h"

#include "capone/proto/capabilities.pb-c.h"
#include "capone/services/capabilities.h"

struct registrant {
    struct cpn_sign_key_public identity;
    struct cpn_channel channel;
};

struct client {
    struct cpn_channel channel;
    struct registrant *waitsfor;
    uint32_t requestid;
};

struct cpn_list registrants;
struct cpn_list clients;

static uint32_t requestid;
static pthread_mutex_t registrants_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

static void relay_capability_for_registrant(struct registrant *r)
{
    Capability *cap = NULL;
    struct client *c = NULL;
    struct cpn_list_entry *it, *next;

    if (cpn_channel_receive_protobuf(&r->channel,
                &capability__descriptor, (ProtobufCMessage **) &cap) < 0)
    {
        /* Kill erroneous registrants */
        pthread_mutex_lock(&registrants_mutex);
        cpn_list_foreach_entry(&registrants, it) {
            if (it->data == r) {
                cpn_list_remove(&registrants, it);
                break;
            }
        }
        free(r);
        pthread_mutex_unlock(&registrants_mutex);

        /* Kill clients waiting for registrant */
        pthread_mutex_lock(&clients_mutex);
        for (it = registrants.head; it; it = next) {
            next = it->next;
            c = (struct client *) it->data;

            if (c->waitsfor != r)
                continue;

            cpn_channel_close(&c->channel);
            cpn_list_remove(&registrants, it);
            free(c);
        }
        pthread_mutex_unlock(&clients_mutex);

        cpn_log(LOG_LEVEL_ERROR, "Unable to receive capability");
        goto out;
    }

    pthread_mutex_lock(&clients_mutex);
    cpn_list_foreach(&clients, it, c) {
        if (c->requestid == cap->requestid) {
            cpn_list_remove(&clients, it);
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    if (!it)
        goto out;

    if (cpn_channel_write_protobuf(&c->channel, &cap->base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to push capability");
    }

out:
    if (cap)
        capability__free_unpacked(cap, NULL);
    free(c);
    return;
}

static void *relay_capabilities()
{
    struct cpn_list_entry *it;
    struct registrant *r;
    fd_set fds;
    int maxfd;

    while (true) {
        FD_ZERO(&fds);
        maxfd = -1;

        if (clients.head == NULL)
            break;

        pthread_mutex_lock(&registrants_mutex);
        cpn_list_foreach(&registrants, it, r) {
            FD_SET(r->channel.fd, &fds);
            maxfd = MAX(maxfd, r->channel.fd);
        }
        pthread_mutex_unlock(&registrants_mutex);

        if (select(maxfd + 1, &fds, NULL, NULL, NULL) == -1)
            continue;

        cpn_list_foreach(&registrants, it, r) {
            if (FD_ISSET(r->channel.fd, &fds))
                relay_capability_for_registrant((struct registrant *) it->data);
        }
    }

    return NULL;
}

static int relay_capability_request(struct cpn_channel *channel,
        const CapabilityRequest *request,
        const struct cpn_cfg *cfg)
{
    Capability cap_message = CAPABILITY__INIT;
    char *host = NULL, *port = NULL;
    struct cpn_channel service_channel;
    struct cpn_sign_key_pair local_keys;
    struct cpn_sign_key_public service_key, invoker_key;
    struct cpn_cap *root_cap = NULL, *ref_cap = NULL;
    const struct cpn_service_plugin *service;
    uint32_t sessionid;
    int ret = 0;

    memset(&service_channel, 0, sizeof(struct cpn_channel));

    if ((ret = cpn_sign_key_pair_from_config(&local_keys, cfg)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to retrieve local key pair from config");
        goto out;
    }

    if (cpn_service_plugin_for_type(&service, request->service_type) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Request for unknown service");
        goto out;
    }

    cpn_sign_key_public_from_proto(&service_key, request->service_identity);

    if ((ret = cpn_proto_initiate_connection(&service_channel,
                    request->service_address, request->service_port,
                    &local_keys, &service_key, CPN_CONNECTION_TYPE_REQUEST)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to initiate connection type to remote service");
        goto out;
    }

    if ((ret = cpn_proto_send_request(&sessionid, &root_cap, &service_channel, service,
                    request->n_parameters, (const char **) request->parameters)) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send request to remote service");
        goto out;
    }

    if (cpn_cap_create_ref(&ref_cap, root_cap, CPN_CAP_RIGHT_EXEC|CPN_CAP_RIGHT_TERM, &invoker_key) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to create referencing capability");
        goto out;
    }

    cap_message.requestid = request->requestid;
    cap_message.sessionid = sessionid;
    cpn_sign_key_public_to_proto(&cap_message.service_identity, &service_key);

    cap_message.capability = malloc(sizeof(CapabilityMessage));
    if (cpn_cap_to_protobuf(cap_message.capability, ref_cap) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to parse capability");
        goto out;
    }

    if ((ret = cpn_channel_write_protobuf(channel, &cap_message.base)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to send requested capability");
        goto out;
    }

out:
    cpn_channel_close(&service_channel);

    cpn_cap_free(root_cap);
    cpn_cap_free(ref_cap);

    free(host);
    free(port);

    return ret;
}

static int invoke_register(struct cpn_channel *channel, struct cpn_opt *opts)
{
    CapabilityRequest *request;
    struct cpn_sign_key_hex requester_hex, service_hex;
    struct cpn_sign_key_public requester, service;
    struct cpn_cfg cfg;
    size_t i;

    if (cpn_cfg_parse(&cfg, opts[0].value.string) < 0) {
        puts("Could not find config");
        return -1;
    }

    while (true) {
        if (cpn_channel_receive_protobuf(channel, &capability_request__descriptor,
                (ProtobufCMessage **) &request) < 0)
        {
            cpn_log(LOG_LEVEL_ERROR, "Error receiving registered capability requests");
            return -1;
        }

        if (cpn_sign_key_public_from_proto(&requester, request->requester_identity) < 0 ||
                cpn_sign_key_public_from_proto(&service, request->service_identity) < 0)
        {
            cpn_log(LOG_LEVEL_ERROR, "Unable to parse remote keys");
            return -1;
        }

        cpn_sign_key_hex_from_key(&requester_hex, &requester);
        cpn_sign_key_hex_from_key(&service_hex, &service);

        printf("request from: %s\n"
               "     service: %s\n"
               "     address: %s\n"
               "        port: %s\n"
               "  parameters: ",
               requester_hex.data, service_hex.data,
               request->service_address, request->service_port);
        for (i = 0; i < request->n_parameters; i++) {
            printf("%s ", request->parameters[i]);
        }

        while (true) {
            int c;

            printf("Accept? [y/n] ");

            c = getchar();

            if (c == 'y') {
                if (relay_capability_request(channel, request, &cfg) < 0)
                    cpn_log(LOG_LEVEL_ERROR, "Unable to relay capability");
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

static int invoke_request(struct cpn_channel *channel)
{
    Capability *capability = NULL;
    struct cpn_sign_key_public service;
    struct cpn_sign_key_hex service_hex;
    struct cpn_cap *cap = NULL;
    char *cap_hex = NULL;
    int err = -1;

    if (cpn_channel_receive_protobuf(channel, &capability__descriptor,
                (ProtobufCMessage **) &capability) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Unable to receive capability");
        goto out;
    }

    if (cpn_sign_key_public_from_proto(&service, capability->service_identity) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to parse service identity");
        goto out;
    }
    cpn_sign_key_hex_from_key(&service_hex, &service);

    if (cpn_cap_from_protobuf(&cap, capability->capability) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to parse capability secret");
        goto out;
    }

    if (cpn_cap_to_string(&cap_hex, cap) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to convert capability");
        goto out;
    }

    printf("service:    %s\n"
           "sessionid:  %"PRIu32"\n"
           "secret:     %s\n",
           service_hex.data, capability->sessionid, cap_hex);

    err = 0;

out:
    if (capability)
        capability__free_unpacked(capability, NULL);
    cpn_cap_free(cap);
    free(cap_hex);

    return err;
}

static int invoke(struct cpn_channel *channel, int argc, const char **argv)
{
    struct cpn_opt register_opts[] = {
        CPN_OPTS_OPT_STRING(0, "--config", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    struct cpn_opt request_opts[] = {
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_ACTION("register", NULL, NULL),
        CPN_OPTS_OPT_ACTION("request", NULL, NULL),
        CPN_OPTS_OPT_END
    };

    opts[0].value.action_opts = register_opts;
    opts[0].value.action_opts = request_opts;

    if (cpn_opts_parse(opts, argc, argv) < 0)
        return -1;

    if (opts[0].set)
        return invoke_register(channel, request_opts);
    else if (opts[1].set)
        return invoke_request(channel);
    else {
        cpn_log(LOG_LEVEL_ERROR, "Unknown parameter '%s'", argv[0]);
        return -1;
    }
}

static int handle_register(struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker)
{
    struct cpn_sign_key_hex hex;
    struct registrant *registrant;
    int n = 0;

    registrant = malloc(sizeof(struct registrant));

    pthread_mutex_lock(&registrants_mutex);
    cpn_list_append(&registrants, registrant);

    memcpy(&registrant->channel, channel, sizeof(struct cpn_channel));
    memcpy(&registrant->identity, invoker, sizeof(struct cpn_sign_key_public));

    pthread_mutex_unlock(&registrants_mutex);

    cpn_sign_key_hex_from_key(&hex, invoker);
    cpn_log(LOG_LEVEL_DEBUG, "Identity %s registered", hex.data);
    cpn_log(LOG_LEVEL_VERBOSE, "%d identities registered", n + 1);

    channel->fd = -1;

    return 0;
}

static int handle_request(struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker,
        CapabilitiesParams__RequestParams *params)
{
    CapabilityRequest request = CAPABILITY_REQUEST__INIT;
    struct cpn_list_entry *it;
    struct registrant *reg = NULL;
    struct client *client;
    int err = 0;

    pthread_mutex_lock(&registrants_mutex);
    cpn_list_foreach(&registrants, it, reg) {
        if (!memcmp(reg->identity.data, params->requested_identity->data.data,
                    sizeof(struct cpn_sign_key_public)))
            break;
    }
    pthread_mutex_unlock(&registrants_mutex);

    if (it == NULL) {
        cpn_log(LOG_LEVEL_ERROR, "Identity specified in capability request is not registered");
        return -1;
    }

    request.requestid = requestid++;

    cpn_sign_key_public_to_proto(&request.requester_identity, invoker);
    request.service_identity = params->service_identity;
    request.service_address = params->service_address;
    request.service_port = params->service_port;
    request.n_parameters = params->n_parameters;
    request.parameters = params->parameters;

    if (cpn_channel_write_protobuf(&reg->channel, &request.base) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to request capability request");
        return -1;
    }

    client = malloc(sizeof(struct client));
    client->requestid = request.requestid;
    client->waitsfor = reg;
    memcpy(&client->channel, channel, sizeof(struct cpn_channel));

    pthread_mutex_lock(&clients_mutex);
    if (clients.head == NULL)
        cpn_spawn(NULL, relay_capabilities, NULL);
    cpn_list_append(&clients, client);
    pthread_mutex_unlock(&clients_mutex);

    channel->fd = -1;

    return err;
}

static int handle(struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    CapabilitiesParams *params = (CapabilitiesParams *) session->parameters;
    UNUSED(cfg);

    switch (params->type) {
        case CAPABILITIES_PARAMS__TYPE__REGISTER:
            return handle_register(channel, invoker);
        case CAPABILITIES_PARAMS__TYPE__REQUEST:
            return handle_request(channel, invoker, params->request_params);
        default:
            return -1;
    }
}

int parse(ProtobufCMessage **out, int argc, const char *argv[])
{
    struct cpn_opt request_opts[] = {
        CPN_OPTS_OPT_SIGKEY(0, "--service-identity", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--service-address", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--service-port", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--service-type", NULL, NULL, false),
        CPN_OPTS_OPT_STRINGLIST(0, "--service-parameters", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_ACTION("register", NULL, NULL),
        CPN_OPTS_OPT_ACTION("request", NULL, NULL),
        CPN_OPTS_OPT_END
    };
    CapabilitiesParams *params;

    opts[1].value.action_opts = request_opts;
    if (cpn_opts_parse(opts, argc, argv) < 0)
        return -1;

    params = malloc(sizeof(CapabilitiesParams));
    capabilities_params__init(params);

    if (opts[0].set) {
        params->type = CAPABILITIES_PARAMS__TYPE__REGISTER;
    } else {
        CapabilitiesParams__RequestParams *rparams;
        uint32_t i;

        rparams = malloc(sizeof(CapabilitiesParams__RequestParams));
        capabilities_params__request_params__init(rparams);

        cpn_sign_key_public_to_proto(&rparams->requested_identity, &request_opts[0].value.sigkey);
        cpn_sign_key_public_to_proto(&rparams->service_identity, &request_opts[1].value.sigkey);
        rparams->service_address = strdup(request_opts[2].value.string);
        rparams->service_port = strdup(request_opts[3].value.string);
        rparams->service_type = strdup(request_opts[4].value.string);

        rparams->n_parameters = request_opts[5].value.stringlist.argc;
        rparams->parameters = malloc(sizeof(char *) * rparams->n_parameters);
        for (i = 0; i < rparams->n_parameters; i++) {
            rparams->parameters[i] = strdup(request_opts[5].value.stringlist.argv[i]);
        }

        params->request_params = rparams;
        params->type = CAPABILITIES_PARAMS__TYPE__REQUEST;
    }

    *out = &params->base;

    return 0;
}

int cpn_capabilities_init_service(const struct cpn_service_plugin **service)
{
    static struct cpn_service_plugin plugin = {
        "Capabilities",
        "capabilities",
        "0.0.1",
        handle,
        invoke,
        parse,
        &capabilities_params__descriptor
    };

    *service = &plugin;

    return 0;
}
