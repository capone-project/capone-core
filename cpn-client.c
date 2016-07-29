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
#include <string.h>
#include <stdio.h>
#include <sodium.h>
#include <inttypes.h>

#include "capone/common.h"
#include "capone/channel.h"
#include "capone/proto.h"
#include "capone/service.h"

static struct cpn_sign_key_pair local_keys;
static struct cpn_sign_key_public remote_key;

static void usage(const char *prog)
{
    printf("USAGE: %s (query|request|connect|terminate)\n"
            "\tquery <CONFIG> <SERVICE_KEY> <HOST> <PORT>\n"
            "\trequest <CONFIG> <INVOKER_KEY> <SERVICE_KEY> <HOST> <PORT> [<PARAMETER>...]\n"
            "\tconnect <CONFIG> <SERVICE_KEY> <HOST> <PORT> <SERVICE> <SESSIONID> <SECRET>\n"
            "\tterminate <CONFIG> <SERVICE_KEY> <HOST> <PORT> <SESSIONID> <CAPABILITY>\n",
            prog);
    exit(-1);
}

static int cmd_query(int argc, char *argv[])
{
    struct cpn_query_results results;
    struct cpn_channel channel;
    char *config, *key, *host, *port;
    size_t i;

    if (argc != 6)
        usage(argv[0]);

    config = argv[2];
    key = argv[3];
    host = argv[4];
    port = argv[5];

    if (cpn_sign_key_pair_from_config_file(&local_keys, config) < 0) {
        puts("Could not parse sign keys");
        return -1;
    }

    if (cpn_sign_key_public_from_hex(&remote_key, key) < 0) {
        puts("Could not parse remote public key");
        return -1;
    }

    if (cpn_proto_initiate_connection(&channel, host, port,
                &local_keys, &remote_key, CPN_CONNECTION_TYPE_QUERY) < 0) {
        puts("Could not establish connection");
        return -1;
    }

    if (cpn_proto_send_query(&results, &channel) < 0) {
        puts("Could not query service");
        return -1;
    }

    printf("%s\n"
            "\tname:     %s\n"
            "\tcategory: %s\n"
            "\ttype:     %s\n"
            "\tversion:  %s\n"
            "\tlocation: %s\n"
            "\tport:     %s\n",
            key,
            results.name,
            results.category,
            results.type,
            results.version,
            results.location,
            results.port);

    for (i = 0; i < results.nparams; i++) {
        struct cpn_parameter *param = &results.params[i];

        printf("\tparam:    %s=%s\n", param->key, param->value);
    }

    cpn_query_results_free(&results);
    cpn_channel_close(&channel);

    return 0;
}

static int cmd_request(int argc, char *argv[])
{
    char invoker_hex[CPN_CAP_SECRET_LEN * 2 + 1], requester_hex[CPN_CAP_SECRET_LEN * 2 + 1];
    const char *config, *invoker, *key, *host, *port;
    struct cpn_cap requester_cap, invoker_cap;
    struct cpn_sign_key_public invoker_key;
    struct cpn_parameter *params = NULL;
    struct cpn_channel channel;
    ssize_t nparams;

    memset(&channel, 0, sizeof(channel));

    if (argc < 7) {
        usage(argv[0]);
    }

    config = argv[2];
    invoker = argv[3];
    key = argv[4];
    host = argv[5];
    port = argv[6];

    if ((nparams = cpn_parameters_parse(&params, argc - 7, argv + 7)) < 0) {
        puts("Could not parse parameters");
        goto out_err;
    }

    if (cpn_sign_key_pair_from_config_file(&local_keys, config) < 0) {
        puts("Could not parse config");
        goto out_err;
    }

    if (cpn_sign_key_public_from_hex(&invoker_key, invoker) < 0) {
        puts("Could not parse remote public key");
        goto out_err;
    }

    if (cpn_sign_key_public_from_hex(&remote_key, key) < 0) {
        puts("Could not parse remote public key");
        goto out_err;
    }

    if (cpn_proto_initiate_connection(&channel, host, port,
                &local_keys, &remote_key, CPN_CONNECTION_TYPE_REQUEST) < 0) {
        puts("Could not establish connection");
        goto out_err;
    }

    if (cpn_proto_send_request(&invoker_cap, &requester_cap,
                &channel, &invoker_key, params, nparams) < 0)
    {
        puts("Unable to request session");
        goto out_err;
    }

    sodium_bin2hex(invoker_hex, sizeof(invoker_hex),
            invoker_cap.secret, CPN_CAP_SECRET_LEN);
    sodium_bin2hex(requester_hex, sizeof(requester_hex),
            requester_cap.secret, CPN_CAP_SECRET_LEN);

    printf("sessionid:          %"PRIu32"\n"
           "invoker-secret:     %s\n"
           "requester-secret:   %s\n",
           invoker_cap.objectid,
           invoker_hex, requester_hex);

    cpn_channel_close(&channel);

    return 0;

out_err:
    cpn_channel_close(&channel);
    cpn_parameters_free(params, nparams);
    return -1;
}

static int cmd_connect(int argc, char *argv[])
{
    const char *config, *key, *host, *port, *service_type, *session, *secret;
    struct cpn_sign_key_public remote_key;
    struct cpn_service service;
    struct cpn_channel channel;
    struct cpn_cap cap;

    if (argc < 9)
        usage(argv[0]);

    config = argv[2];
    key = argv[3];
    host = argv[4];
    port = argv[5];
    service_type = argv[6];
    session = argv[7];
    secret = argv[8];

    if (cpn_sign_key_pair_from_config_file(&local_keys, config) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (cpn_sign_key_public_from_hex(&remote_key, key) < 0) {
        puts("Could not parse remote public key");
        return -1;
    }

    if (cpn_service_from_type(&service, service_type) < 0) {
        printf("Invalid service %s\n", service_type);
        return -1;
    }

    if (cpn_cap_parse(&cap, session, secret, CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM) < 0) {
        puts("Invalid capability");
        return -1;
    }

    if (cpn_proto_initiate_connection(&channel, host, port,
                &local_keys, &remote_key, CPN_CONNECTION_TYPE_CONNECT) < 0) {
        puts("Could not start connection");
        return -1;
    }

    if (cpn_proto_initiate_session(&channel, &cap) < 0) {
        puts("Could not connect to session");
        return -1;
    }

    if (service.invoke(&channel, argc - 9, argv + 9) < 0) {
        puts("Could not invoke service");
        return -1;
    }

    cpn_channel_close(&channel);

    return 0;
}

static int cmd_terminate(int argc, char *argv[])
{
    struct cpn_sign_key_public remote_key;
    struct cpn_sign_key_pair local_keys;
    struct cpn_channel channel;
    struct cpn_cap cap;
    const char *config, *key, *host, *port, *session, *capability;

    if (argc != 8)
        usage(argv[0]);

    config = argv[2];
    key = argv[3];
    host = argv[4];
    port = argv[5];
    session = argv[6];
    capability = argv[7];

    if (cpn_sign_key_pair_from_config_file(&local_keys, config) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (cpn_sign_key_public_from_hex(&remote_key, key) < 0) {
        puts("Could not parse remote public key");
        return -1;
    }

    if (cpn_cap_parse(&cap, session, capability, CPN_CAP_RIGHT_TERM) < 0) {
        puts("Invalid capability\n");
        return -1;
    }

    if (cpn_proto_initiate_connection(&channel, host, port,
                &local_keys, &remote_key, CPN_CONNECTION_TYPE_TERMINATE) < 0) {
        puts("Could not start connection");
        return -1;
    }

    if (cpn_proto_initiate_termination(&channel, &cap) < 0) {
        puts("Could not initiate termination");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        usage(argv[0]);

    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts("cpn-connect " VERSION "\n"
             "Copyright (C) 2016 Patrick Steinhardt\n"
             "License GPLv3: GNU GPL version 3 <http://gnu.org/licenses/gpl.html>.\n"
             "This is free software; you are free to change and redistribute it.\n"
             "There is NO WARRANTY, to the extent permitted by the law.");
        return 0;
    }

    if (cpn_service_register_builtins() < 0) {
        puts("Could not initialize services");
        return -1;
    }

    if (sodium_init() < 0) {
        puts("Could not init libsodium");
        return -1;
    }

    if (!strcmp(argv[1], "query"))
        return cmd_query(argc, argv);
    if (!strcmp(argv[1], "request"))
        return cmd_request(argc, argv);
    else if (!strcmp(argv[1], "connect"))
        return cmd_connect(argc, argv);
    else if (!strcmp(argv[1], "terminate"))
        return cmd_terminate(argc, argv);

    usage(argv[0]);

    return 0;
}
