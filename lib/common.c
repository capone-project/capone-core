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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/channel.h"
#include "lib/cfg.h"
#include "lib/log.h"

#include "common.h"

int sd_spawn(struct sd_thread *t, thread_fn fn, void *payload)
{
    pthread_t stub;

    return pthread_create(t ? &t->t : &stub, NULL, fn, payload);
}

int sd_kill(struct sd_thread *t)
{
    return pthread_cancel(t->t);
}

int parse_uint32t(uint32_t *out, const char *num)
{
    int saved_errno;
    int ret = 0;

    saved_errno = errno;
    errno = 0;

    *out = strtol(num, NULL, 10);
    if (errno != 0) {
        sd_log(LOG_LEVEL_ERROR, "Invalid session ID %s", num);
        ret = -1;
        goto out;
    }

out:
    errno = saved_errno;
    return ret;
}
