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

#include <stdio.h>
#include <string.h>

#include "bench.h"

#include "capone/channel.h"
#include "capone/client.h"
#include "capone/common.h"
#include "capone/opts.h"
#include "capone/socket.h"

#include "capone/crypto/sign.h"

#define PORT 43281
#define REPEATS 1000

struct client_args {
    struct cpn_sign_key_pair client_keys;
    struct cpn_sign_key_pair server_keys;
};

static void *client(void *payload)
{
    struct client_args *args;
    struct cpn_channel channel;
    uint64_t start, end, time;
    int i;

    args = (struct client_args *) payload;

    if (cpn_bench_set_affinity(2) < 0) {
        puts("Unable to set sched affinity");
        return NULL;
    }

    time = 0;

    for (i = 0; i < REPEATS; i++) {
        if (cpn_channel_init_from_host(&channel, "127.0.0.1", PORT, CPN_CHANNEL_TYPE_TCP) < 0) {
            puts("Unable to init connection");
            return NULL;
        }

        start = cpn_bench_nsecs();
        if (cpn_client_connect(&channel, "127.0.0.1", PORT,
                    &args->server_keys, &args->client_keys.pk) < 0)
        {
            puts("Unable to connect to server");
            return NULL;
        }
        end = cpn_bench_nsecs();

        if (cpn_channel_close(&channel) < 0) {
            puts("Unable to close channel");
        }

        time += end - start;
    }

    printf("conn (nsec):\t%"PRIu64"\n", time / REPEATS);

    return NULL;
}

int main(int argc, const char *argv[])
{
    struct cpn_thread t;
    struct client_args args;
    struct cpn_socket socket;
    struct cpn_channel channel;
    uint64_t start, end, time;
    int i;

    UNUSED(argc);
    UNUSED(argv);

    if (cpn_bench_set_affinity(3) < 0) {
        puts("Unable to set sched affinity");
        return -1;
    }

    if (cpn_sign_key_pair_generate(&args.server_keys) < 0) {
        puts("Unable to generate server sign key");
        return -1;
    }
    if (cpn_sign_key_pair_generate(&args.client_keys) < 0) {
        puts("Unable to generate client sign key");
        return -1;
    }

    if (cpn_socket_init(&socket, NULL, PORT, CPN_CHANNEL_TYPE_TCP) < 0) {
        puts("Unable to init socket");
        return -1;
    }

    if (cpn_socket_listen(&socket) < 0) {
        puts("Unable to listen");
        return -1;
    }

    if (cpn_spawn(&t, client, &args) < 0) {
        puts("Unable to spawn client");
        return -1;
    }

    time = 0;

    for (i = 0; i < REPEATS; i++) {
        if (cpn_socket_accept(&socket, &channel) < 0) {
            puts("Unable to accept connection");
            return -1;
        }

        start = cpn_bench_nsecs();
        if (cpn_server_await_encryption(&channel, &args.server_keys, &args.client_keys.pk) < 0) {
            puts("Unable to await encryption");
            return -1;
        }
        end = cpn_bench_nsecs();

        if (cpn_channel_close(&channel) < 0) {
            puts("Unable to close channel");
        }

        time += end - start;
    }

    if (cpn_join(&t, NULL) < 0) {
        puts("Unable to await client thread");
        return -1;
    }

    printf("await (nsec):\t%"PRIu64"\n", time / REPEATS);

    return 0;
}

