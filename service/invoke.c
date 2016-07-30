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

#include "invoke.h"

#include "capone/channel.h"
#include "capone/common.h"
#include "capone/log.h"
#include "capone/proto.h"
#include "capone/service.h"

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct cpn_parameter **out)
{
    static const struct cpn_parameter params[] = {
        { "service-identity", NULL },
        { "service-address", NULL },
        { "service-port", NULL },
        { "service-type", NULL },
        { "service-args", NULL },
        { "sessionid", NULL },
    };

    *out = params;

    return ARRAY_SIZE(params);
}

static int invoke(struct cpn_channel *channel, int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);
    UNUSED(channel);

    return 0;
}

static int handle(struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    const char *service_identity, *service_address, *service_type,
          *service_port, *sessionid_string, *secret_string;
    const char **service_params = NULL;
    struct cpn_service service;
    struct cpn_sign_key_pair local_keys;
    struct cpn_sign_key_public remote_key;
    struct cpn_channel remote_channel;
    struct cpn_cap cap;
    size_t nparams;

    UNUSED(channel);
    UNUSED(invoker);

    cpn_parameters_get_value(&service_identity,
            "service-identity", session->parameters, session->nparameters);
    cpn_parameters_get_value(&service_address,
            "service-address", session->parameters, session->nparameters);
    cpn_parameters_get_value(&service_port,
            "service-port", session->parameters, session->nparameters);
    cpn_parameters_get_value(&service_type,
            "service-type", session->parameters, session->nparameters);
    cpn_parameters_get_value(&sessionid_string,
            "sessionid", session->parameters, session->nparameters);
    cpn_parameters_get_value(&secret_string,
            "secret", session->parameters, session->nparameters);

    nparams = cpn_parameters_get_values(&service_params,
            "service-args", session->parameters, session->nparameters);

    if (service_identity == NULL || service_address == NULL || service_type == NULL
            || service_port == NULL || sessionid_string == NULL || secret_string == NULL)
    {
        cpn_log(LOG_LEVEL_ERROR, "Not all parameters were set");
        goto out;
    }

    if (cpn_sign_key_pair_from_config(&local_keys, cfg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not parse config");
        goto out;
    }

    if (cpn_sign_key_public_from_hex(&remote_key, service_identity) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not parse remote public key");
        goto out;
    }

    if (cpn_cap_parse(&cap, sessionid_string, secret_string, CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Invalid capability");
        goto out;
    }

    if (cpn_service_from_type(&service, service_type) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unknown service type");
        goto out;
    }

    if (cpn_proto_initiate_connection(&remote_channel, service_address, service_port,
                &local_keys, &remote_key, CPN_CONNECTION_TYPE_CONNECT) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not start invoke connection");
        goto out;
    }

    if (cpn_proto_initiate_session(&remote_channel, &cap) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not connect to session");
        goto out;
    }

    if (service.invoke(&remote_channel, nparams, (char **) service_params) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not invoke service");
        goto out;
    }

out:
    free(service_params);
    return 0;
}

int cpn_invoke_init_service(struct cpn_service *service)
{
    service->category = "Invoke";
    service->type = "invoke";
    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}

