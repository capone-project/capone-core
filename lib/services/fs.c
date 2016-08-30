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

#include "capone/common.h"
#include "capone/opts.h"
#include "capone/service.h"

#include "capone/services/fs.h"
#include "capone/proto/fs.pb-c.h"

static int invoke(struct cpn_channel *channel,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    UNUSED(channel);
    UNUSED(session);
    UNUSED(cfg);

    return 0;
}

static int serve(struct cpn_channel *channel,
        const struct cpn_sign_pk *invoker,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    FilesystemParams *params = (FilesystemParams *) session->parameters;

    UNUSED(params);
    UNUSED(channel);
    UNUSED(invoker);
    UNUSED(cfg);

    return 0;
}

static int parse(ProtobufCMessage **out, int argc, const char *argv[])
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_END
    };

    if (cpn_opts_parse(opts, argc, argv) < 0)
        return -1;

    *out = NULL;

    return 0;
}

int cpn_fs_init_service(const struct cpn_service_plugin **out)
{
    static struct cpn_service_plugin plugin = {
        "Filesystem",
        "fs",
        1,
        serve,
        invoke,
        parse,
        &filesystem_params__descriptor
    };

    *out = &plugin;

    return 0;
}
