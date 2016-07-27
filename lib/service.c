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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "capone/common.h"
#include "capone/log.h"
#include "capone/service.h"

#include "service/capabilities.h"
#include "service/exec.h"
#include "service/invoke.h"
#include "service/synergy.h"
#include "service/test.h"
#include "service/xpra.h"

static int fill_service(struct cpn_service *service, const char *type)
{
    if (!strcmp(type, "capabilities"))
        return cpn_capabilities_init_service(service);
    if (!strcmp(type, "exec"))
        return cpn_exec_init_service(service);
    if (!strcmp(type, "invoke"))
        return cpn_invoke_init_service(service);
    if (!strcmp(type, "synergy"))
        return cpn_synergy_init_service(service);
    if (!strcmp(type, "xpra"))
        return cpn_xpra_init_service(service);
    if (!strcmp(type, "test"))
        return cpn_test_init_service(service);

    return -1;
}

int cpn_service_from_type(struct cpn_service *out, const char *type)
{
    memset(out, 0, sizeof(struct cpn_service));

    return fill_service(out, type);
}

int cpn_services_from_config_file(struct cpn_service **out, const char *file)
{
    struct cpn_cfg cfg;
    int ret;

    if (cpn_cfg_parse(&cfg, file) < 0) {
        return -1;
    }

    ret = cpn_services_from_config(out, &cfg);
    cpn_cfg_free(&cfg);

    return ret;
}

int cpn_services_from_config(struct cpn_service **out, const struct cpn_cfg *cfg)
{
    struct cpn_service *services = NULL;
    int i, count = 0;

    for (i = 0; (size_t) i < cfg->numsections; i++) {
        if (strcmp(cfg->sections[i].name, "service"))
            continue;

        count++;
        services = realloc(services, sizeof(struct cpn_service) * count);

        if (cpn_service_from_section(&services[count - 1], &cfg->sections[i]) < 0) {
            goto out_err;
        }
    }

    *out = services;

    return count;

out_err:
    for (i = 0; i < count; i++)
        cpn_service_free(&services[i]);
    free(services);

    return -1;
}

int cpn_service_from_config_file(struct cpn_service *out, const char *name, const char *file)
{
    struct cpn_cfg cfg;
    int ret;

    if (cpn_cfg_parse(&cfg, file) < 0) {
        return -1;
    }

    ret = cpn_service_from_config(out, name, &cfg);
    cpn_cfg_free(&cfg);

    return ret;
}

int cpn_service_from_config(struct cpn_service *out, const char *name, const struct cpn_cfg *cfg)
{
    unsigned i, j;

    for (i = 0; i < cfg->numsections; i++) {
        struct cpn_cfg_section *s = &cfg->sections[i];
        if (strcmp(s->name, "service"))
            continue;

        for (j = 0; j < s->numentries; j++) {
            struct cpn_cfg_entry *e = &s->entries[j];

            if (strcmp(e->name, "name"))
                continue;
            if (!strcmp(e->value, name))
                return cpn_service_from_section(out, s);
        }
    }

    cpn_log(LOG_LEVEL_ERROR, "Could not find service '%s'", name);

    return -1;
}

int cpn_service_from_section(struct cpn_service *out, const struct cpn_cfg_section *section)
{
    struct cpn_service service;
    unsigned i;

    memset(&service, 0, sizeof(service));

#define MAYBE_ADD_ENTRY(field, entry, value)                                    \
    if (!strcmp(#field, entry)) {                                               \
        if (service.field != NULL) {                                         \
            cpn_log(LOG_LEVEL_ERROR, "Service config has been specified twice"); \
            goto out_err;                                                       \
        }                                                                       \
        service.field = strdup(value);                                          \
        continue;                                                               \
    }

    for (i = 0; i < section->numentries; i++) {
        const char *entry = section->entries[i].name,
            *value = section->entries[i].value;

        MAYBE_ADD_ENTRY(name, entry, value);
        MAYBE_ADD_ENTRY(type, entry, value);
        MAYBE_ADD_ENTRY(port, entry, value);
        MAYBE_ADD_ENTRY(location, entry, value);

        cpn_log(LOG_LEVEL_ERROR, "Unknown service config '%s'", entry);
        goto out_err;
    }

#undef MAYBE_ADD_ENTRY

    if (service.name == NULL ||
            service.type == NULL ||
            service.port == NULL ||
            service.location == NULL)
    {
        cpn_log(LOG_LEVEL_ERROR, "Not all service parameters were set");
        goto out_err;
    }

    if (fill_service(&service, service.type) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unknown service type '%s'", service.type);
        goto out_err;
    }

    memcpy(out, &service, sizeof(service));

    return 0;

out_err:
    cpn_service_free(&service);

    return -1;
}

void cpn_service_free(struct cpn_service *service)
{
    free(service->name);
    free(service->type);
    free(service->port);
    free(service->location);

    memset(service, 0, sizeof(struct cpn_service));
}
