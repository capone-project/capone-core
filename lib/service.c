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

#include "lib/common.h"
#include "lib/log.h"
#include "lib/service.h"

#include "service/capabilities.h"
#include "service/exec.h"
#include "service/invoke.h"
#include "service/synergy.h"
#include "service/test.h"
#include "service/xpra.h"

static int fill_service(struct sd_service *service, const char *type)
{
    if (!strcmp(type, "capabilities"))
        return sd_capabilities_init_service(service);
    if (!strcmp(type, "exec"))
        return sd_exec_init_service(service);
    if (!strcmp(type, "invoke"))
        return sd_invoke_init_service(service);
    if (!strcmp(type, "synergy"))
        return sd_synergy_init_service(service);
    if (!strcmp(type, "xpra"))
        return sd_xpra_init_service(service);
    if (!strcmp(type, "test"))
        return sd_test_init_service(service);

    return -1;
}

int sd_service_from_type(struct sd_service *out, const char *type)
{
    memset(out, 0, sizeof(struct sd_service));

    return fill_service(out, type);
}

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
    unsigned i, j;

    for (i = 0; i < cfg->numsections; i++) {
        struct cfg_section *s = &cfg->sections[i];
        if (strcmp(s->name, "service"))
            continue;

        for (j = 0; j < s->numentries; j++) {
            struct cfg_entry *e = &s->entries[j];

            if (strcmp(e->name, "name"))
                continue;
            if (!strcmp(e->value, name))
                return sd_service_from_section(out, s);
        }
    }

    sd_log(LOG_LEVEL_ERROR, "Could not find service '%s'", name);

    return -1;
}

int sd_service_from_section(struct sd_service *out, const struct cfg_section *section)
{
    struct sd_service service;
    unsigned i;

    memset(&service, 0, sizeof(service));

#define MAYBE_ADD_ENTRY(field, entry, value)                                    \
    if (!strcmp(#field, entry)) {                                               \
        if (service.field != NULL) {                                         \
            sd_log(LOG_LEVEL_ERROR, "Service config has been specified twice"); \
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

        sd_log(LOG_LEVEL_ERROR, "Unknown service config '%s'", entry);
        goto out_err;
    }

#undef MAYBE_ADD_ENTRY

    if (service.name == NULL ||
            service.type == NULL ||
            service.port == NULL ||
            service.location == NULL)
    {
        sd_log(LOG_LEVEL_ERROR, "Not all service parameters were set");
        goto out_err;
    }

    if (fill_service(&service, service.type) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unknown service type '%s'", service.type);
        goto out_err;
    }

    memcpy(out, &service, sizeof(service));

    return 0;

out_err:
    sd_service_free(&service);

    return -1;
}

void sd_service_free(struct sd_service *service)
{
    free(service->name);
    free(service->type);
    free(service->port);
    free(service->location);

    memset(service, 0, sizeof(struct sd_service));
}

int sd_service_parameters_get_value(const char **out, const char *value, const struct sd_service_parameter *parameters, size_t n)
{
    const char **values;
    int nvalues;

    *out = NULL;

    nvalues = sd_service_parameters_get_values(&values, value, parameters, n);
    if (nvalues < 0) {
        sd_log(LOG_LEVEL_WARNING, "Could not retrieve parameter value '%s'", value);
        goto out_err;
    } else if (nvalues == 0) {
        sd_log(LOG_LEVEL_WARNING, "Requested parameter value '%s' not present", value);
        goto out_err;
    } else if (nvalues > 1) {
        sd_log(LOG_LEVEL_WARNING, "Requested parameter value '%s' has more than one value", value);
        goto out_err;
    }

    *out = values[0];
    free(values);

    return 0;

out_err:
    free(values);
    return -1;
}

int sd_service_parameters_get_values(const char ***out, const char *value, const struct sd_service_parameter *parameters, size_t n)
{
    const struct sd_service_parameter *param;
    const char **values = NULL;
    int nvalues = 0;
    size_t i;

    *out = NULL;

    for (i = 0; i < n; i++) {
        param = &parameters[i];

        if (!strcmp(param->key, value) && param->value != NULL) {
            values = realloc(values, sizeof(char *) * (nvalues + 1));
            values[nvalues++] = param->value;
        }
    }

    *out = values;

    return nvalues;
}

void sd_service_parameters_free(struct sd_service_parameter *params, size_t nparams)
{
    size_t i;

    if (!params || nparams == 0)
        return;

    for (i = 0; i < nparams; i++) {
        free((void *) params[i].key);
        free((void *) params[i].value);
    }

    free(params);
}
