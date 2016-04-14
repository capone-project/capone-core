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

#include "lib/channel.h"
#include "lib/common.h"
#include "lib/log.h"
#include "lib/proto.h"
#include "lib/service.h"

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct sd_service_parameter **out)
{
    static const struct sd_service_parameter params[] = {
        { "service-identity", 0, NULL },
        { "service-address", 0, NULL },
        { "service-port", 0, NULL },
        { "service-type", 0, NULL },
        { "service-args", 0, NULL },
        { "sessionid", 0, NULL },
        { "sessionkey", 0, NULL },
    };

    *out = params;

    return ARRAY_SIZE(params);
}

static int invoke(struct sd_channel *channel, int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);
    UNUSED(channel);

    return 0;
}

static int handle(struct sd_channel *channel,
        const struct sd_session *session,
        const struct cfg *cfg)
{
    const char *service_identity, *service_address, *service_type,
          *service_port, *sessionid_string;
    const char **service_params = NULL;
    struct sd_service service;
    struct sd_sign_key_pair local_keys;
    struct sd_sign_key_public remote_key;
    struct sd_channel remote_channel;
    uint32_t sessionid;
    size_t nparams;

    UNUSED(channel);

    sd_service_parameters_get_value(&service_identity,
            "service-identity", session->parameters, session->nparameters);
    sd_service_parameters_get_value(&service_address,
            "service-address", session->parameters, session->nparameters);
    sd_service_parameters_get_value(&service_port,
            "service-port", session->parameters, session->nparameters);
    sd_service_parameters_get_value(&service_type,
            "service-type", session->parameters, session->nparameters);
    sd_service_parameters_get_value(&sessionid_string,
            "sessionid", session->parameters, session->nparameters);

    nparams = sd_service_parameters_get_values(&service_params,
            "service-args", session->parameters, session->nparameters);

    if (service_identity == NULL || service_address == NULL || service_type == NULL
            || service_port == NULL || sessionid_string == NULL)
    {
        sd_log(LOG_LEVEL_ERROR, "Not all parameters were set");
        goto out;
    }

    if (sd_sign_key_pair_from_config(&local_keys, cfg) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not parse config");
        goto out;
    }

    if (sd_sign_key_public_from_hex(&remote_key, service_identity) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not parse remote public key");
        goto out;
    }

    if (parse_uint32t(&sessionid, sessionid_string) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Invalid session ID");
        goto out;
    }

    if (sd_service_from_type(&service, service_type) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unknown service type");
        goto out;
    }

    if (sd_proto_initiate_connection(&remote_channel, service_address, service_port,
                &local_keys, &remote_key, SD_CONNECTION_TYPE_CONNECT) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not start invoke connection");
        goto out;
    }

    if (sd_proto_initiate_session(&remote_channel, sessionid) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not connect to session");
        goto out;
    }

    if (service.invoke(&remote_channel, nparams, (char **) service_params) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not invoke service");
        goto out;
    }

out:
    free(service_params);
    return 0;
}

int sd_invoke_init_service(struct sd_service *service)
{
    service->category = "Invoke";
    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}

