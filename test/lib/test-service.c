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
#include "test-service.h"
#include "test/lib/test.pb-c.h"

static uint8_t buf[1024];

static int invoke(struct cpn_channel *channel,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    UNUSED(session);
    UNUSED(cfg);
    return cpn_channel_receive_data(channel, buf, sizeof(buf));
}

static int handle(struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    TestParams *params;

    UNUSED(cfg);
    UNUSED(invoker);

    params = (TestParams *) session->parameters;

    return cpn_channel_write_data(channel, (uint8_t *) params->msg, strlen(params->msg));
}

static int parse(ProtobufCMessage **out, int argc, const char *argv[])
{
    TestParams *params;

    *out = NULL;

    if (argc > 1)
        return -1;

    params = malloc(sizeof(TestParams));
    test_params__init(params);
    if (argc) {
        params->msg = strdup(argv[0]);
    }

    *out = &params->base;

    return 0;
}

int cpn_test_init_service(const struct cpn_service_plugin **out)
{
    static struct cpn_service_plugin plugin = {
        "Test",
        "test",
        "0.0.1",
        handle,
        invoke,
        parse,
        &test_params__descriptor
    };

    *out = &plugin;

    return 0;
}

uint8_t *cpn_test_service_get_data(void)
{
    return buf;
}
