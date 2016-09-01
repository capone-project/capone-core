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

#include "capone/channel.h"
#include "capone/common.h"
#include "capone/log.h"
#include "capone/opts.h"
#include "capone/proto.h"
#include "capone/service.h"

#include "capone/services/invoke.h"
#include "capone/proto/invoke.pb-c.h"

static int invoke(struct cpn_channel *channel, int argc, const char **argv,
        const struct cpn_cfg *cfg)
{
    UNUSED(argc);
    UNUSED(argv);
    UNUSED(channel);
    UNUSED(cfg);

    return 0;
}

static int handle(struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    InvokeParams *params;
    const struct cpn_service_plugin *plugin;
    struct cpn_sign_key_pair local_keys;
    struct cpn_sign_key_public service_key;
    struct cpn_channel remote_channel;
    struct cpn_cap *cap = NULL;

    UNUSED(channel);
    UNUSED(invoker);

    params = (InvokeParams *) session->parameters;

    if (cpn_sign_key_pair_from_config(&local_keys, cfg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not parse config");
        goto out;
    }

    if (cpn_cap_from_protobuf(&cap, params->cap) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid capability");
        goto out;
    }

    if (cpn_service_plugin_for_type(&plugin, params->service_type) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unknown service type");
        goto out;
    }

    if (cpn_sign_key_public_from_proto(&service_key, params->service_identity) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid Unknown service key");
        goto out;
    }

    if (cpn_proto_initiate_connection(&remote_channel,
                params->service_address, params->service_port,
                &local_keys, &service_key, CPN_CONNECTION_TYPE_CONNECT) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not start invoke connection");
        goto out;
    }

    if (cpn_proto_initiate_session(&remote_channel, params->sessionid, cap) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not connect to session");
        goto out;
    }

    if (plugin->client_fn(&remote_channel,
                params->n_service_parameters, (const char **) params->service_parameters, cfg) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Could not invoke service");
        goto out;
    }

out:
    cpn_cap_free(cap);

    return 0;
}

static int parse(ProtobufCMessage **out, int argc, const char *argv[])
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_UINT32(0, "--sessionid", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--secret", NULL, NULL, false),
        CPN_OPTS_OPT_SIGKEY(0, "--service-identity", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--service-address", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--service-port", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--service-type", NULL, NULL, false),
        CPN_OPTS_OPT_STRINGLIST(0, "--service-parameters", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    InvokeParams *params = NULL;
    struct cpn_cap *cap = NULL;
    uint32_t i;
    int err = -1;

    if (cpn_opts_parse(opts, argc, argv) < 0)
        goto out;

    if (cpn_cap_from_string(&cap, opts[1].value.string) < 0)
        goto out;

    params = malloc(sizeof(InvokeParams));
    invoke_params__init(params);
    params->sessionid = opts[0].value.uint32;
    cpn_cap_to_protobuf(&params->cap, cap);

    cpn_sign_key_public_to_proto(&params->service_identity, &opts[2].value.sigkey);
    params->service_address = strdup(opts[3].value.string);
    params->service_port = strdup(opts[4].value.string);
    params->service_type = strdup(opts[5].value.string);

    params->n_service_parameters = opts[6].value.stringlist.argc;
    params->service_parameters = malloc(sizeof(char *) * params->n_service_parameters);
    for (i = 0; i < params->n_service_parameters; i++) {
        params->service_parameters[i] = strdup(opts[6].value.stringlist.argv[i]);
    }

    *out = &params->base;
    err = 0;

out:
    if (params)
        invoke_params__free_unpacked(params, NULL);
    cpn_cap_free(cap);
    return err;
}

int cpn_invoke_init_service(const struct cpn_service_plugin **out)
{
    static struct cpn_service_plugin plugin = {
        "Invoke",
        "invoke",
        "0.0.1",
        handle,
        invoke,
        parse,
        &invoke_params__descriptor
    };

    *out = &plugin;

    return 0;
}

