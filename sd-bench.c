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

#ifdef HAVE_SCHED
# define __USE_GNU
#  include <sched.h>
# undef __USE_GNU
#endif

#include "lib/channel.h"
#include "lib/common.h"
#include "lib/keys.h"
#include "lib/server.h"

#define PORT "43281"
#define DATA_LEN (1024 * 1024 * 100)

static char encrypt;
static struct sd_symmetric_key key;

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
    struct sd_channel channel;
    uint8_t *data = malloc(DATA_LEN);
    uint64_t start, end;

    if (set_affinity(2) < 0) {
        puts("Unable to set sched affinity");
        goto out;
    }

    UNUSED(payload);

    if (sd_channel_init_from_host(&channel, "127.0.0.1", PORT, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Unable to init connection");
        goto out;
    }
    if (sd_channel_connect(&channel) < 0) {
        puts("Unable to connect to server");
        goto out;
    }

    if (encrypt) {
        sd_channel_enable_encryption(&channel, &key, SD_CHANNEL_NONCE_CLIENT);
    }

    start = rdtsc64();
    if (sd_channel_write_data(&channel, data, DATA_LEN) < 0) {
        puts("Unable to write data");
        goto out;
    }
    end = rdtsc64();

    printf("Cycles spent writing data:\t%"PRIu64"\n", end - start);

out:
    free(data);

    return NULL;
}

static void usage(const char *executable)
{
    printf("USAGE: %s [--encrypted|--plain]\n", executable);
}

int main(int argc, char *argv[])
{
    struct sd_server server;
    struct sd_channel channel;
    uint8_t *data = malloc(DATA_LEN);
    uint64_t start, end;

    if (argc > 2) {
        usage(argv[0]);
        return -1;
    }

    if (argc <= 1 || !strcmp(argv[1] , "--plain")) {
        encrypt = 0;
    } else if (!strcmp(argv[1], "--encrypted")) {
        encrypt = 1;
        sd_symmetric_key_generate(&key);
    } else {
        usage(argv[0]);
        return -1;
    }

    if (set_affinity(3) < 0) {
        puts("Unable to set sched affinity");
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

    if (sd_spawn(NULL, client, NULL) < 0) {
        puts("Unable to spawn client");
        return -1;
    }

    if (sd_server_accept(&server, &channel) < 0) {
        puts("Unable to accept connection");
        return -1;
    }

    if (encrypt) {
        sd_channel_enable_encryption(&channel, &key, SD_CHANNEL_NONCE_SERVER);
    }

    start = rdtsc64();
    if (sd_channel_receive_data(&channel, data, DATA_LEN) < 0) {
        puts("Unable to receive data");
        return -1;
    }
    end = rdtsc64();

    printf("Cycles spent receiving data:\t%"PRIu64"\n", end - start);

    return 0;
}
