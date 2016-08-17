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

#include <sodium.h>

#include "capone/common.h"
#include "capone/global.h"
#include "capone/list.h"
#include "capone/log.h"

#include "capone/service.h"

typedef int (*init_fn)(void);

static init_fn init_fns[] = {
    sodium_init,
    cpn_service_plugin_register_builtins
};

static struct cpn_list shutdown_fns = CPN_LIST_INIT;

int cpn_global_init(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(init_fns); i++) {
        if (init_fns[i]() < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Could not perform global initialization");
            return -1;
        }
    }

    return 0;
}

int cpn_global_shutdown(void)
{
    struct cpn_list_entry *it;

    cpn_list_foreach_entry(&shutdown_fns, it) {
        cpn_global_shutdown_fn fn = (cpn_global_shutdown_fn) (intptr_t) it->data;

        if (fn() < 0)
            cpn_log(LOG_LEVEL_ERROR, "Could not invoke shutdown function");
    }

    return 0;
}

int cpn_global_on_shutdown(cpn_global_shutdown_fn fn)
{
    return cpn_list_append(&shutdown_fns, (void *) (intptr_t) fn);
}
