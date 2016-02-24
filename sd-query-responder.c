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

#include "proto/encryption.pb-c.h"
#include "proto/query.pb-c.h"

#include "lib/common.h"
#include "lib/server.h"
#include "lib/service.h"

static struct sd_key_pair keys;
static struct sd_service service;

static int handle_connect(struct sd_channel *channel)
{
    QueryResults results = QUERY_RESULTS__INIT;
    QueryResults__Parameter **parameters;
    const struct sd_service_parameter *params;
    int i, n;

    if (await_encryption(channel, &keys) < 0) {
        puts("Unable to negotiate encryption");
        return -1;
    }

    results.name = service.name;
    results.type = service.type;
    results.subtype = service.subtype;
    results.version = (char *) service.version();
    results.location = service.location;
    results.port = service.connectport;

    n = service.parameters(&params);
    parameters = malloc(sizeof(QueryResults__Parameter *) * n);
    for (i = 0; i < n; i++) {
        QueryResults__Parameter *parameter = malloc(sizeof(QueryResults__Parameter));
        query_results__parameter__init(parameter);

        parameter->key = (char *) params[i].name;
        parameter->n_value = params[i].numvalues;
        parameter->value = (char **) params[i].values;

        parameters[i] = parameter;
    }
    results.parameters = parameters;
    results.n_parameters = n;

    sd_channel_write_protobuf(channel, (ProtobufCMessage *) &results);

    return 0;
}

int main(int argc, char *argv[])
{
    const char *config, *servicename;
    struct sd_channel channel;
    struct sd_server server;

    if (argc != 3) {
        printf("USAGE: %s <CONFIG> <SERVICENAME>\n", argv[0]);
        return -1;
    }

    config = argv[1];
    servicename = argv[2];

    if (sodium_init() < 0) {
        puts("Could not init libsodium");
        return -1;
    }

    if (sd_service_from_config_file(&service, servicename, config) < 0) {
        puts("Could not parse services");
        return -1;
    }

    if (sd_key_pair_from_config_file(&keys, config) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (sd_server_init(&server, NULL, service.queryport, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Could not set up server");
        return -1;
    }

    if (sd_server_listen(&server) < 0) {
        puts("Could not start listening");
        return -1;
    }

    while (1) {
        if (sd_server_accept(&server, &channel) < 0) {
            puts("Could not accept connection");
            return -1;
        }

        handle_connect(&channel);
        sd_channel_close(&channel);
    }

    sd_server_close(&server);

    return 0;
}
