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

int sd_services_from_config_file(struct sd_service **out, const char *file)
{
    struct cfg cfg;
    int ret;

    if (cfg_parse(&cfg, file) < 0) {
        return -1;
    }

    ret = sd_services_from_config(out, &cfg);
    cfg_free(&cfg);

    return ret;
}

int sd_services_from_config(struct sd_service **out, const struct cfg *cfg)
{
    struct sd_service *services = NULL;
    int i, count = 0;

    for (i = 0; (size_t) i < cfg->numsections; i++) {
        if (strcmp(cfg->sections[i].name, "service"))
            continue;

        count++;
        services = realloc(services, sizeof(struct sd_service) * count);

        if (sd_service_from_section(&services[count - 1], &cfg->sections[i]) < 0) {
            goto out_err;
        }
    }

    *out = services;

    return count;

out_err:
    for (i = 0; i < count; i++)
        sd_service_free(&services[i]);
    free(services);

    return -1;
}

int sd_service_from_config_file(struct sd_service *out, const char *name, const char *file)
{
    struct cfg cfg;
    int ret;

    if (cfg_parse(&cfg, file) < 0) {
        return -1;
    }

    ret = sd_service_from_config(out, name, &cfg);
    cfg_free(&cfg);

    return ret;
}

int sd_service_from_config(struct sd_service *out, const char *name, const struct cfg *cfg)
{
    unsigned i;

    for (i = 0; i < cfg->numsections; i++) {
        if (!strcmp(cfg->sections[i].name, name))
            return sd_service_from_section(out, &cfg->sections[i]);
    }

    return -1;
}

int sd_service_from_section(struct sd_service *out, const struct cfg_section *section)
{
    char *name = NULL, *type = NULL, *port = NULL;
    unsigned i;

    for (i = 0; i < section->numentries; i++) {
        const char *entry = section->entries[i].name,
            *value = section->entries[i].value;

        if (!strcmp(entry, "name")) {
            if (name) {
                sd_log(LOG_LEVEL_ERROR, "Service config 'name' has been specified twice");
                goto out_err;
            }

            name = strdup(value);
        } else if (!strcmp(entry, "type")) {
            if (type) {
                sd_log(LOG_LEVEL_ERROR, "Service config 'type' has been specified twice");
                goto out_err;
            }

            type = strdup(value);
        } else if (!strcmp(entry, "port")) {
            if (port) {
                sd_log(LOG_LEVEL_ERROR, "Service config 'port' has been specified twice");
                goto out_err;
            }

            port = strdup(value);
        } else {
            sd_log(LOG_LEVEL_ERROR, "Unknown service config '%s'", entry);
            goto out_err;
        }
    }

    assert(name && type && port);

    out->name = name;
    out->type = type;
    out->port = port;

    return 0;

out_err:
    free(name);
    free(type);
    free(port);

    return -1;
}

void sd_service_free(struct sd_service *service)
{
    free(service->name);
}
