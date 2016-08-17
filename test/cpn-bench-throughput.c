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
#include "capone/common.h"
#include "capone/keys.h"
#include "capone/opts.h"
#include "capone/server.h"

#define PORT "43281"

struct client_args {
    uint32_t datalen;
    uint32_t blocklen;
    uint32_t repeats;
};

static char encrypt;
static struct cpn_symmetric_key key;

static void *client(void *payload)
{
    struct client_args *args = (struct client_args *) payload;
    struct cpn_channel channel;
    uint8_t *data = malloc(args->datalen);
    uint64_t start, end;
    uint32_t i;

    if (cpn_bench_set_affinity(2) < 0) {
        puts("Unable to set sched affinity");
        goto out;
    }

    if (cpn_channel_init_from_host(&channel, "127.0.0.1", PORT, CPN_CHANNEL_TYPE_TCP) < 0) {
        puts("Unable to init connection");
        goto out;
    }
    if (cpn_channel_connect(&channel) < 0) {
        puts("Unable to connect to server");
        goto out;
    }

    if (encrypt) {
        cpn_channel_enable_encryption(&channel, &key, CPN_CHANNEL_NONCE_CLIENT);
    }

    cpn_channel_set_blocklen(&channel, args->blocklen);

    start = cpn_bench_nsecs();
    for (i = 0; i < args->repeats; i++) {
        if (cpn_channel_write_data(&channel, data, args->datalen) < 0) {
            puts("Unable to write data");
            goto out;
        }
    }
    end = cpn_bench_nsecs();

    printf("send (ns):\t%"PRIu64"\n", (end - start) / args->repeats);

out:
    free(data);

    return NULL;
}

int main(int argc, const char *argv[])
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_COUNTER('e', "--encrypt", "Benchmark sending encrypted text"),
        CPN_OPTS_OPT_UINT32('d', "--data-length", "Length of data to send", "LENGTH", false),
        CPN_OPTS_OPT_UINT32('b', "--block-length", "Length of blocks to split by", "LENGTH", false),
        CPN_OPTS_OPT_END
    };
    struct client_args args;
    struct cpn_thread t;
    struct cpn_server server;
    struct cpn_channel channel;
    uint8_t *data;
    uint64_t start, end;
    uint32_t i;

    if (cpn_opts_parse_cmd(opts, argc, argv) < 0)
        return -1;

    encrypt = opts[0].value.counter;
    args.datalen = opts[1].value.uint32;
    args.blocklen = opts[2].value.uint32;

    data = malloc(args.datalen);

    /* Always average over 1GB of data sent */
    args.repeats = (1024 * 1024 * 1024) / args.datalen;

    if (cpn_bench_set_affinity(3) < 0) {
        puts("Unable to set sched affinity");
        return -1;
    }

    if (cpn_server_init(&server, NULL, PORT, CPN_CHANNEL_TYPE_TCP) < 0) {
        puts("Unable to init server");
        return -1;
    }

    if (cpn_server_listen(&server) < 0) {
        puts("Unable to listen");
        return -1;
    }

    if (cpn_spawn(&t, client, &args) < 0) {
        puts("Unable to spawn client");
        return -1;
    }

    if (cpn_server_accept(&server, &channel) < 0) {
        puts("Unable to accept connection");
        return -1;
    }

    if (encrypt) {
        cpn_channel_enable_encryption(&channel, &key, CPN_CHANNEL_NONCE_SERVER);
    }

    cpn_channel_set_blocklen(&channel, args.blocklen);

    start = cpn_bench_nsecs();
    for (i = 0; i < args.repeats; i++) {
        if (cpn_channel_receive_data(&channel, data, args.datalen) < 0) {
            puts("Unable to receive data");
            return -1;
        }
    }
    end = cpn_bench_nsecs();

    if (cpn_join(&t, NULL) < 0) {
        puts("Unable to await client thread");
        return -1;
    }

    printf("recv (ns):\t%"PRIu64"\n", (end - start) / args.repeats);

    return 0;
}
