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

#ifndef SD_LIB_COMMON_H
#define SD_LIB_COMMON_H

#include <inttypes.h>
#include <pthread.h>

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
#define MIN(a, b) ((a) > (b) ? (b) : (a))

#define UNUSED(x) (void)(x)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

typedef void *(*thread_fn)(void *);
struct sd_thread {
    pthread_t t;
};

int sd_spawn(struct sd_thread *t, thread_fn fn, void *payload);
int sd_kill(struct sd_thread *t);
int sd_join(struct sd_thread *t, void **out);

int parse_uint32t(uint32_t *out, const char *num);

#endif
