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
#include "capone/global.h"
#include "capone/opts.h"
#include "capone/proto.h"
#include "capone/service.h"

static struct cpn_opt request_opts[] = {
    CPN_OPTS_OPT_SIGKEY(0, "--invoker-key",
            "For whom to request the capability", "KEY", false),
    CPN_OPTS_OPT_STRINGLIST(0, "--parameters", NULL, "PARAMETER", false),
    CPN_OPTS_OPT_END
};

static struct cpn_opt connect_opts[] = {
    CPN_OPTS_OPT_STRING('c', "--service-type",
            "Type of service which is to be invoked", "TYPE", false),
    CPN_OPTS_OPT_STRING(0, "--session-id", NULL, "ID", false),
    CPN_OPTS_OPT_STRING('c', "--session-cap", NULL, "CAP", false),
    CPN_OPTS_OPT_STRINGLIST(0, "--parameters", NULL, "PARAMETER", false),
    CPN_OPTS_OPT_END
};

static struct cpn_opt terminate_opts[] = {
    CPN_OPTS_OPT_STRING(0, "--session-id", NULL, "ID", false),
    CPN_OPTS_OPT_STRING('c', "--session-cap", NULL, "CAP", false),
    CPN_OPTS_OPT_END
};

static struct cpn_opt opts[] = {
    CPN_OPTS_OPT_STRING('c', "--config",
            "Path to configuration file", "CFGFILE", false),
    CPN_OPTS_OPT_SIGKEY(0, "--remote-key",
            "Public signature key of the host to query", "KEY", false),
    CPN_OPTS_OPT_STRING(0, "--remote-host",
            "Network address of the host to query", "ADDRESS", false),
    CPN_OPTS_OPT_STRING(0, "--remote-port",
            "Port of the host to query", "PORT", false),
    CPN_OPTS_OPT_ACTION("query", NULL, NULL),
    CPN_OPTS_OPT_ACTION("request", NULL, request_opts),
    CPN_OPTS_OPT_ACTION("connect", NULL, connect_opts),
    CPN_OPTS_OPT_ACTION("terminate", NULL, terminate_opts),
    CPN_OPTS_OPT_END
};

static struct cpn_sign_key_pair local_keys;

static struct cpn_sign_key_public remote_key;
static const char *remote_host;
static const char *remote_port;

static int cmd_query(void)
{
    struct cpn_sign_key_hex hex;
    struct cpn_query_results results;
    struct cpn_channel channel;
    size_t i;

    if (cpn_proto_initiate_connection(&channel, remote_host, remote_port,
                &local_keys, &remote_key, CPN_CONNECTION_TYPE_QUERY) < 0) {
        puts("Could not establish connection");
        return -1;
    }

    if (cpn_proto_send_query(&results, &channel) < 0) {
        puts("Could not query service");
        return -1;
    }

    cpn_sign_key_hex_from_key(&hex, &remote_key);

    printf("%s\n"
            "\tname:     %s\n"
            "\tcategory: %s\n"
            "\ttype:     %s\n"
            "\tversion:  %s\n"
            "\tlocation: %s\n"
            "\tport:     %s\n",
            hex.data,
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

static int cmd_request(const struct cpn_sign_key_public *invoker_key,
        const struct cpn_opts_stringlist *parameters)
{
    char invoker_hex[CPN_CAP_SECRET_LEN * 2 + 1], requester_hex[CPN_CAP_SECRET_LEN * 2 + 1];
    struct cpn_cap requester_cap, invoker_cap;
    struct cpn_parameter *params = NULL;
    struct cpn_channel channel;
    ssize_t nparams;

    memset(&channel, 0, sizeof(channel));

    if ((nparams = cpn_parameters_parse(&params, parameters->argc, parameters->argv)) < 0) {
        puts("Could not parse parameters");
        goto out_err;
    }

    if (cpn_proto_initiate_connection(&channel, remote_host, remote_port,
                &local_keys, &remote_key, CPN_CONNECTION_TYPE_REQUEST) < 0) {
        puts("Could not establish connection");
        goto out_err;
    }

    if (cpn_proto_send_request(&invoker_cap, &requester_cap,
                &channel, invoker_key, params, nparams) < 0)
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

static int cmd_connect(const char *service_type, const char *session,
        const char *capability,
        const struct cpn_opts_stringlist *parameters)
{
    struct cpn_service service;
    struct cpn_channel channel;
    struct cpn_cap cap;

    if (cpn_service_from_type(&service, service_type) < 0) {
        printf("Invalid service %s\n", service_type);
        return -1;
    }

    if (cpn_cap_parse(&cap, session, capability, CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM) < 0) {
        puts("Invalid capability");
        return -1;
    }

    if (cpn_proto_initiate_connection(&channel, remote_host, remote_port,
                &local_keys, &remote_key, CPN_CONNECTION_TYPE_CONNECT) < 0) {
        puts("Could not start connection");
        return -1;
    }

    if (cpn_proto_initiate_session(&channel, &cap) < 0) {
        puts("Could not connect to session");
        return -1;
    }

    if (service.invoke(&channel, parameters->argc, parameters->argv) < 0) {
        puts("Could not invoke service");
        return -1;
    }

    cpn_channel_close(&channel);

    return 0;
}

static int cmd_terminate(const char *session, const char *capability)
{
    struct cpn_channel channel;
    struct cpn_cap cap;

    if (cpn_cap_parse(&cap, session, capability, CPN_CAP_RIGHT_TERM) < 0) {
        puts("Invalid capability\n");
        return -1;
    }

    if (cpn_proto_initiate_connection(&channel, remote_host, remote_port,
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

int main(int argc, const char *argv[])
{
    if (cpn_global_init() < 0)
        return -1;

    if (cpn_opts_parse_cmd(opts, argc, argv) < 0) {
        return -1;
    }

    if (cpn_sign_key_pair_from_config_file(&local_keys, opts[0].value.string) < 0) {
        puts("Could not parse config");
        return -1;
    }

    memcpy(&remote_key, &opts[1].value.sigkey, sizeof(struct cpn_sign_key_public));
    remote_host = opts[2].value.string;
    remote_port = opts[3].value.string;

    if (opts[4].set)
        return cmd_query();
    else if (opts[5].set)
        return cmd_request(&request_opts[0].value.sigkey,
                &request_opts[1].value.stringlist);
    else if (opts[6].set)
        return cmd_connect(connect_opts[0].value.string,
               connect_opts[1].value.string,
               connect_opts[2].value.string,
               &connect_opts[3].value.stringlist);
    else if (opts[7].set)
        return cmd_terminate(terminate_opts[0].value.string,
                terminate_opts[1].value.string);

    return 0;
}
