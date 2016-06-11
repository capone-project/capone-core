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

#include "config.h"

#ifdef HAVE_SCHED
# define __USE_GNU
#  include <sched.h>
#  include <pthread.h>
# undef __USE_GNU
#endif

#ifdef HAVE_CLOCK_GETTIME
# include <time.h>
#else
# include <sys/time.h>
#endif

#include "lib/channel.h"
#include "lib/common.h"
#include "lib/keys.h"
#include "lib/proto.h"
#include "lib/server.h"

#define PORT "43281"
#define REPEATS 1000

static uint32_t blocklen;

struct client_args {
    struct sd_sign_key_pair client_keys;
    struct sd_sign_key_pair server_keys;
};

static uint64_t nsecs(void)
{
#ifdef HAVE_CLOCK_GETTIME
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);

    return t.tv_sec * 1000000000 + t.tv_nsec;
#else
    struct timeval t;

    gettimeofday(&t, NULL);

    return t.tv_sec * 1000000000 + t.tv_usec * 1000;
#endif
}

static int set_affinity(uint8_t cpu)
{
#ifdef HAVE_SCHED
    cpu_set_t mask;
    pthread_t t;

    t = pthread_self();

    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);

    return pthread_setaffinity_np(t, sizeof(mask), &mask);
#else
    UNUSED(cpu);
    return 0;
#endif
}

static void *client(void *payload)
{
    struct client_args *args;
    struct sd_channel channel;
    uint64_t start, end;
    int i;

    args = (struct client_args *) payload;

    if (set_affinity(2) < 0) {
        puts("Unable to set sched affinity");
        return NULL;
    }

    if (sd_channel_init_from_host(&channel, "127.0.0.1", PORT, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Unable to init connection");
        return NULL;
    }

    start = nsecs();
    if (sd_channel_connect(&channel) < 0) {
        puts("Unable to connect to server");
        return NULL;
    }

    if (sd_channel_set_blocklen(&channel, blocklen) < 0) {
        puts("Unable to set block length");
        return NULL;
    }

    for (i = 0; i < REPEATS; i++) {
        if (sd_proto_initiate_encryption(&channel, &args->client_keys, &args->server_keys.pk) < 0) {
            puts("Unable to initiate encryption");
            return NULL;
        }
    }
    end = nsecs();

    printf("conn (nsec):\t%"PRIu64"\n", (end - start) / REPEATS);

    return NULL;
}

int main(int argc, char *argv[])
{
    struct sd_thread t;
    struct client_args args;
    struct sd_server server;
    struct sd_channel channel;
    uint64_t start, end;
    int i;

    if (argc != 2) {
        printf("USAGE: %s <BLOCKLEN>\n", argv[0]);
        return -1;
    }

    if (parse_uint32t(&blocklen, argv[1]) < 0) {
        printf("Could not parse block length %s\n", argv[1]);
        return -1;
    }

    if (set_affinity(3) < 0) {
        puts("Unable to set sched affinity");
        return -1;
    }

    if (sd_sign_key_pair_generate(&args.server_keys) < 0) {
        puts("Unable to generate server sign key");
        return -1;
    }
    if (sd_sign_key_pair_generate(&args.client_keys) < 0) {
        puts("Unable to generate client sign key");
        return -1;
    }

    if (sd_server_init(&server, NULL, PORT, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Unable to init server");
        return -1;
    }

    if (sd_server_listen(&server) < 0) {
        puts("Unable to listen");
        return -1;
    }

    if (sd_spawn(&t, client, &args) < 0) {
        puts("Unable to spawn client");
        return -1;
    }

    if (sd_server_accept(&server, &channel) < 0) {
        puts("Unable to accept connection");
        return -1;
    }

    if (sd_channel_set_blocklen(&channel, blocklen) < 0) {
        puts("Unable to set block length");
        return -1;
    }

    start = nsecs();
    for (i = 0; i < REPEATS; i++) {
        if (sd_proto_await_encryption(&channel, &args.server_keys, &args.client_keys.pk) < 0) {
            puts("Unable to await encryption");
            return -1;
        }
    }
    end = nsecs();

    if (sd_join(&t, NULL) < 0) {
        puts("Unable to await client thread");
        return -1;
    }

    printf("await (nsec):\t%"PRIu64"\n", (end - start) / REPEATS);

    return 0;
}

