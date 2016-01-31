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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "service.h"

int sd_service_from_config_file(struct sd_service *out, const char *file)
{
    struct cfg cfg;
    int ret;

    if (cfg_parse(&cfg, file) < 0) {
        return -1;
    }

    ret = sd_service_from_config(out, &cfg);
    cfg_free(&cfg);

    return ret;
}

int sd_service_from_config(struct sd_service *out, const struct cfg *cfg)
{
    out->name = cfg_get_str_value(cfg, "service", "name");
    assert(out->name);

    out->port = cfg_get_int_value(cfg, "service", "port");
    assert(out->port);

    return 0;
}

void sd_service_free(struct sd_service *service)
{
    free(service->name);
}
