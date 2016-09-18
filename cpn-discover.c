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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include "capone/cfg.h"
#include "capone/client.h"
#include "capone/common.h"
#include "capone/global.h"
#include "capone/list.h"
#include "capone/log.h"
#include "capone/opts.h"
#include "capone/socket.h"

#include "capone/proto/discovery.pb-c.h"

#define LISTEN_PORT 6668

static struct cpn_sign_key_pair local_keys;

static void print_announcement(struct cpn_discovery_results *announce)
{
    struct cpn_sign_key_hex hex;
    uint32_t i;

    cpn_sign_key_hex_from_key(&hex, &announce->identity);

    printf("%s - %s (v%s)\n", announce->name, hex.data, announce->version);

    for (i = 0; i < announce->nservices; i++) {
        printf("\t%s -> %s (%s)\n", announce->services[i].port,
                announce->services[i].name, announce->services[i].category);
    }
}

static void undirected_discovery()
{
    struct cpn_list known_keys = CPN_LIST_INIT;
    struct cpn_channel channel;

    channel.fd = -1;

    if (cpn_channel_init_from_host(&channel, "224.0.0.1", "6667", CPN_CHANNEL_TYPE_UDP) < 0) {
        puts("Unable to initialize channel");
        goto out;
    }

    while (true) {
        if (cpn_client_discovery_probe(&channel, &known_keys) < 0) {
            puts("Unable to write protobuf");
            goto out;
        } else {
            cpn_log(LOG_LEVEL_DEBUG, "Sent probe message");
        }

        while (true) {
            struct cpn_discovery_results results;
            struct cpn_sign_key_public *key;
            struct cpn_list_entry *it;
            struct pollfd pfd[1];
            int err;

            pfd[0].fd = channel.fd;
            pfd[0].events = POLLIN;

            err = poll(pfd, 1, 5000);

            if (err < 0) {
                printf("Unable to await announcement: %s", strerror(errno));
                goto out;
            } else if (err == 0) {
                break;
            } else if (cpn_client_discovery_handle_announce(&results, &channel) < 0) {
                puts("Unable to handle announce");
                continue;
            }

            cpn_list_foreach(&known_keys, it, key) {
                if (!memcmp(key->data, results.identity.data,
                            sizeof(struct cpn_sign_key_public)))
                {
                    struct cpn_sign_key_hex hex;
                    cpn_sign_key_hex_from_key(&hex, &results.identity);
                    cpn_log(LOG_LEVEL_DEBUG, "Ignoring known key %s", hex.data);
                    continue;
                }
            }

            key = malloc(sizeof(struct cpn_sign_key_public));
            memcpy(key, results.identity.data, sizeof(struct cpn_sign_key_public));
            cpn_list_append(&known_keys, key);

            print_announcement(&results);
            cpn_discovery_results_clear(&results);
        }
    }

out:
    cpn_channel_close(&channel);
}

static void directed_discovery(const struct cpn_sign_key_public *remote_key,
        const char *host, const char *port)
{
    struct cpn_discovery_results results;
    struct cpn_channel channel;

    if (cpn_client_connect(&channel, host, port, &local_keys, remote_key) < 0) {
        puts("Unable to connect");
    }

    if (cpn_client_discovery_probe(&channel, NULL) < 0) {
        puts("Unable to send directed discover");
        goto out;
    }

    if (cpn_client_discovery_handle_announce(&results, &channel) < 0) {
        puts("Unable to handle announce");
        goto out;
    }

    print_announcement(&results);
    cpn_discovery_results_clear(&results);
out:
    cpn_channel_close(&channel);
}

int main(int argc, const char *argv[])
{
    static struct cpn_opt directed_opts[] = {
        CPN_OPTS_OPT_SIGKEY(0, "--remote-key",
                "Public signature key of the host to query", "KEY", false),
        CPN_OPTS_OPT_STRING(0, "--remote-host",
                "Network address of the host to query", "ADDRESS", false),
        CPN_OPTS_OPT_STRING(0, "--remote-port",
                "Port of the host to query", "PORT", false),
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('c', "--config", "Configuration file", "FILE", false),
        CPN_OPTS_OPT_ACTION("broadcast", NULL, NULL),
        CPN_OPTS_OPT_ACTION("direct", NULL, directed_opts),
        CPN_OPTS_OPT_COUNTER('v', "--verbose", "Verbosity"),
        CPN_OPTS_OPT_END
    };

    if (cpn_global_init() < 0)
        return -1;

    if (cpn_opts_parse_cmd(opts, argc, argv) < 0)
        return -1;

    if (opts[3].set) {
        switch (opts[3].value.counter) {
            case 0:
                cpn_log_set_level(LOG_LEVEL_ERROR);
                break;
            case 1:
                cpn_log_set_level(LOG_LEVEL_WARNING);
                break;
            case 2:
                cpn_log_set_level(LOG_LEVEL_VERBOSE);
                break;
            case 3:
                cpn_log_set_level(LOG_LEVEL_TRACE);
                break;
            default:
                break;
        }
    }

    if (opts[1].set) {
        undirected_discovery();
    } else if (opts[2].set) {
        directed_discovery(&directed_opts[0].value.sigkey,
                directed_opts[1].value.string,
                directed_opts[1].value.string);
    } else {
        puts("No action specified");
    }

    return 0;
}
