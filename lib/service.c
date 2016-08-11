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
#include <pthread.h>

#include "capone/common.h"
#include "capone/list.h"
#include "capone/log.h"
#include "capone/service.h"

#include "capone/services/capabilities.h"
#include "capone/services/exec.h"
#include "capone/services/invoke.h"
#include "capone/services/synergy.h"
#include "capone/services/xpra.h"

static struct cpn_list plugins;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int find_service(struct cpn_service *service, const char *type)
{
    struct cpn_list_entry *it;
    struct cpn_service *s;

    cpn_list_foreach(&plugins, it, s) {
        if (!strcmp(s->type, type)) {
            service->category = s->category;
            service->handle = s->handle;
            service->invoke = s->invoke;
            service->parameters = s->parameters;
            service->type = s->type;
            service->version = s->version;
            return 0;
        }
    }

    return -1;
}

int cpn_service_register(struct cpn_service *service)
{
    struct cpn_list_entry *it;
    struct cpn_service *s;
    int err = 0;

    pthread_mutex_lock(&mutex);

    cpn_list_foreach(&plugins, it, s) {
        if (!strcmp(s->type, service->type)) {
            err = -1;
            goto out;
        }
    }

    s = malloc(sizeof(struct cpn_service));
    memcpy(s, service, sizeof(struct cpn_service));
    cpn_list_append(&plugins, s);

out:
    pthread_mutex_unlock(&mutex);
    return err;
}

int cpn_service_register_builtins(void)
{
    int (*initializers[])(struct cpn_service *) = {
        cpn_capabilities_init_service,
        cpn_exec_init_service,
        cpn_invoke_init_service,
        cpn_synergy_init_service,
        cpn_xpra_init_service,
    };
    struct cpn_service service;
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(initializers); i++) {
        if (initializers[i](&service) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to initialize service");
            continue;
        }

        cpn_service_register(&service);
    }

    return 0;
}

int cpn_service_from_type(struct cpn_service *out, const char *type)
{
    memset(out, 0, sizeof(struct cpn_service));

    return find_service(out, type);
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

    if (find_service(&service, service.type) < 0) {
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
    free(service->port);
    free(service->location);

    memset(service, 0, sizeof(struct cpn_service));
}
