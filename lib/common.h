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

#define MAX(a, b) ((a) >= (b) ? (a) : (b))
#define UNUSED(x) (void)(x)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

typedef void (*thread_fn)(void *);

struct sd_channel;
struct sd_sign_key_pair;
struct sd_sign_key_public;

int spawn(thread_fn fn, void *payload);

int initiate_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_sign_key_public *remote_sign_key);
int await_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        struct sd_sign_key_public *remote_sign_key);
