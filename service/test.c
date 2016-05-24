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

#include "lib/common.h"
#include "lib/channel.h"
#include "lib/service.h"

#include "test.h"

static uint8_t buf[1024];

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct sd_service_parameter **out)
{
    static const struct sd_service_parameter params[] = {
        { "test", NULL },
    };

    *out = params;
    return ARRAY_SIZE(params);
}

static int invoke(struct sd_channel *channel, int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);
    return sd_channel_receive_data(channel, buf, sizeof(buf));
}

static int handle(struct sd_channel *channel,
        const struct sd_session *session,
        const struct cfg *cfg)
{
    UNUSED(cfg);

    return sd_channel_write_data(channel,
            (uint8_t *) session->parameters[0].value,
            strlen(session->parameters[0].value));
}

int sd_test_init_service(struct sd_service *service)
{
    service->category = "Test";
    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}

uint8_t *sd_test_service_get_data(void)
{
    return buf;
}
