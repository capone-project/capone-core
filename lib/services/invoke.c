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

#include "capone/channel.h"
#include "capone/common.h"
#include "capone/log.h"
#include "capone/opts.h"
#include "capone/proto.h"
#include "capone/service.h"

#include "capone/services/invoke.h"

static int invoke(struct cpn_channel *channel, int argc, const char **argv)
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
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_SIGKEY(0, "--service-identity", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--service-address", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--service-port", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--service-type", NULL, NULL, false),
        CPN_OPTS_OPT_STRINGLIST(0, "--service-parameters", NULL, NULL, false),
        CPN_OPTS_OPT_UINT32(0, "--sessionid", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--secret", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const struct cpn_service_plugin *plugin;
    struct cpn_sign_key_pair local_keys;
    struct cpn_channel remote_channel;
    struct cpn_cap *cap = NULL;

    UNUSED(channel);
    UNUSED(invoker);

    if (cpn_opts_parse(opts, session->argc, session->argv) < 0) {
        goto out;
    }

    if (cpn_sign_key_pair_from_config(&local_keys, cfg) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not parse config");
        goto out;
    }

    if (cpn_cap_from_string(&cap, opts[6].value.string) < 0)
    {
        cpn_log(LOG_LEVEL_ERROR, "Invalid capability");
        goto out;
    }

    if (cpn_service_plugin_for_type(&plugin, opts[3].value.string) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unknown service type");
        goto out;
    }

    if (cpn_proto_initiate_connection(&remote_channel,
                opts[1].value.string, opts[2].value.string,
                &local_keys, &opts[0].value.sigkey, CPN_CONNECTION_TYPE_CONNECT) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not start invoke connection");
        goto out;
    }

    if (cpn_proto_initiate_session(&remote_channel, opts[5].value.uint32, cap) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not connect to session");
        goto out;
    }

    if (plugin->invoke(&remote_channel, opts[4].value.stringlist.argc, opts[4].value.stringlist.argv) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not invoke service");
        goto out;
    }

out:
    cpn_cap_free(cap);

    return 0;
}

int cpn_invoke_init_service(const struct cpn_service_plugin **out)
{
    static struct cpn_service_plugin plugin = {
        "Invoke",
        "invoke",
        "0.0.1",
        handle,
        invoke
    };

    *out = &plugin;

    return 0;
}

