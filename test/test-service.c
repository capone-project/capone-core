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

#include "capone/common.h"
#include "capone/channel.h"
#include "capone/service.h"

#include "test.h"

static uint8_t buf[1024];

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct cpn_parameter **out)
{
    static const struct cpn_parameter params[] = {
        { "test", NULL },
    };

    *out = params;
    return ARRAY_SIZE(params);
}

static int invoke(struct cpn_channel *channel, int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);
    return cpn_channel_receive_data(channel, buf, sizeof(buf));
}

static int handle(struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    UNUSED(cfg);
    UNUSED(invoker);

    return cpn_channel_write_data(channel,
            (uint8_t *) session->parameters[0].value,
            strlen(session->parameters[0].value));
}

int cpn_test_init_service(struct cpn_service *service)
{
    service->category = "Test";
    service->type = "test";
    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}

uint8_t *cpn_test_service_get_data(void)
{
    return buf;
}
