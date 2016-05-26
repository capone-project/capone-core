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
# undef __USE_GNU
#endif

#include "lib/channel.h"
#include "lib/common.h"
#include "lib/keys.h"
#include "lib/proto.h"
#include "lib/server.h"

#define PORT "43281"
#define REPEATS 1000

struct client_args {
    struct sd_sign_key_pair client_keys;
    struct sd_sign_key_pair server_keys;
};

static uint64_t rdtsc64(void)
{
    uint32_t hi, lo;
        __asm__ __volatile__(
            "xorl %%eax, %%eax\n\t"
            "cpuid\n\t"
            "rdtsc"
        : "=a"(lo), "=d"(hi)
        : /* no inputs */
        : "rbx", "rcx");
    return ((uint64_t)hi << (uint64_t)32) | (uint64_t)lo;
}

static int set_affinity(uint8_t cpu)
{
#ifdef HAVE_SCHED
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    return sched_setaffinity(0, sizeof(mask), &mask);
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

    if (sd_channel_connect(&channel) < 0) {
        puts("Unable to connect to server");
        return NULL;
    }

    start = rdtsc64();
    for (i = 0; i < REPEATS; i++) {
        if (sd_proto_initiate_encryption(&channel, &args->client_keys, &args->server_keys.pk) < 0) {
            puts("Unable to initiate encryption");
            return NULL;
        }
    }
    end = rdtsc64();

    printf("Cycles spent calculating shared secret:\t%"PRIu64"\n", (end - start) / REPEATS);

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

    if (argc != 1) {
        printf("USAGE: %s\n", argv[0]);
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

    start = rdtsc64();
    for (i = 0; i < REPEATS; i++) {
        if (sd_proto_await_encryption(&channel, &args.server_keys, &args.client_keys.pk) < 0) {
            puts("Unable to await encryption");
            return -1;
        }
    }
    end = rdtsc64();

    if (sd_join(&t, NULL) < 0) {
        puts("Unable to await client thread");
        return -1;
    }

    printf("Cycles spent calculating shared secret:\t%"PRIu64"\n", (end - start) / REPEATS);

    return 0;
}

