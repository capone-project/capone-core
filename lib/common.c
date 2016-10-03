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
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "capone/channel.h"
#include "capone/cfg.h"
#include "capone/log.h"
#include "capone/common.h"

#define HEXCHARS "1234567890abcdefABCDEF"

int cpn_spawn(struct cpn_thread *t, thread_fn fn, void *payload)
{
    pthread_t stub;

    return pthread_create(t ? &t->t : &stub, NULL, fn, payload);
}

int cpn_kill(struct cpn_thread *t)
{
    return pthread_cancel(t->t);
}

int cpn_join(struct cpn_thread *t, void **out)
{
    return pthread_join(t->t, out);
}

int parse_uint32t(uint32_t *out, const char *num)
{
    int saved_errno;
    long int result;
    int ret = 0;

    if (strspn(num, "1234567890") != strlen(num)) {
        cpn_log(LOG_LEVEL_ERROR, "uint32_t %s contains invalid chars", num);
        return -1;
    }


    saved_errno = errno;
    errno = 0;

    result = strtol(num, NULL, 10);
    if (errno != 0) {
        cpn_log(LOG_LEVEL_ERROR, "Could not parse uint32t %s", num);
        ret = -1;
        goto out;
    } else if (result < 0 || result > UINT32_MAX) {
        cpn_log(LOG_LEVEL_ERROR, "Parsing %s results in overflow", num);
        ret = -1;
        goto out;
    }

    *out = result;

out:
    errno = saved_errno;
    return ret;
}

int parse_hex(uint8_t *out, uint32_t outlen, const char *hex, uint32_t hexlen)
{
    uint32_t i;
    const char *end;

    if (hex == NULL)
        return -1;

    for (i = 0; i < hexlen; i++)
        if (hex[i] == '\0' || memchr(HEXCHARS, hex[i], strlen(HEXCHARS)) == NULL)
            return -1;

    if (sodium_hex2bin(out, outlen, hex, hexlen, NULL, NULL, &end) < 0)
        return -1;

    if (outlen * 2 != hexlen)
        return -1;

    if (end != (hex + hexlen))
        return -1;

    return 0;
}
