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

#include "capone/client.h"
#include "capone/common.h"
#include "capone/channel.h"
#include "capone/global.h"
#include "capone/log.h"
#include "capone/opts.h"
#include "capone/service.h"

static struct cpn_opt request_opts[] = {
    CPN_OPTS_OPT_STRINGLIST(0, "--parameters", NULL, "PARAMETER", true),
    CPN_OPTS_OPT_STRING('c', "--service-type",
            "Type of service which is to be invoked", "TYPE", false),
    CPN_OPTS_OPT_END
};

static struct cpn_opt connect_opts[] = {
    CPN_OPTS_OPT_STRING(0, "--service-type",
            "Type of service which is to be invoked", "TYPE", false),
    CPN_OPTS_OPT_UINT32(0, "--session-id", NULL, "ID", false),
    CPN_OPTS_OPT_STRING('c', "--session-cap", NULL, "CAP", false),
    CPN_OPTS_OPT_END
};

static struct cpn_opt terminate_opts[] = {
    CPN_OPTS_OPT_UINT32(0, "--session-id", NULL, "ID", false),
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
    CPN_OPTS_OPT_UINT32(0, "--remote-port",
            "Port of the host to query", "PORT", false),
    CPN_OPTS_OPT_COUNTER('v', "--verbose", "Control logging verbosity"),
    CPN_OPTS_OPT_ACTION("query", NULL, NULL),
    CPN_OPTS_OPT_ACTION("request", NULL, request_opts),
    CPN_OPTS_OPT_ACTION("connect", NULL, connect_opts),
    CPN_OPTS_OPT_ACTION("terminate", NULL, terminate_opts),
    CPN_OPTS_OPT_END
};

static struct cpn_cfg cfg;

static struct cpn_sign_key_pair local_keys;

static struct cpn_sign_key_public remote_key;
static const char *remote_host;
static uint32_t remote_port;

static int cmd_query(void)
{
    struct cpn_sign_key_hex hex;
    struct cpn_query_results results;
    struct cpn_channel channel;

    if (cpn_client_connect(&channel, remote_host, remote_port,
                &local_keys, &remote_key) < 0)
    {
        puts("Could not establish connection");
        return -1;
    }

    if (cpn_client_query_service(&results, &channel) < 0) {
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
            "\tport:     %"PRIu32"\n",
            hex.data,
            results.name,
            results.category,
            results.type,
            results.version,
            results.location,
            results.port);

    cpn_channel_close(&channel);

    return 0;
}

static int cmd_request(const char *service_type, const struct cpn_opts_stringlist *parameters)
{
    ProtobufCMessage *params = NULL;
    const struct cpn_service_plugin *plugin;
    struct cpn_cap *cap = NULL;
    struct cpn_channel channel;
    char *cap_hex = NULL;
    uint32_t sessionid;
    int err = -1;

    memset(&channel, 0, sizeof(channel));

    if (cpn_service_plugin_for_type(&plugin, service_type) < 0) {
        printf("Could not find service plugin for type %s\n", service_type);
        goto out_err;
    }

    if (plugin->parse_fn && plugin->parse_fn(&params, parameters->argc, parameters->argv) < 0) {
        printf("Could not parse parameters\n");
        goto out_err;
    }

    if (cpn_client_connect(&channel, remote_host, remote_port,
                &local_keys, &remote_key) < 0)
    {
        puts("Could not establish connection");
        goto out_err;
    }

    if (cpn_client_request_session(&sessionid, &cap, &channel, params) < 0) {
        puts("Unable to request session");
        goto out_err;
    }

    if (cpn_cap_to_string(&cap_hex, cap) < 0)
    {
        puts("Invalid capability");
        goto out_err;
    }

    printf("sessionid:  %"PRIu32"\n"
           "capability: %s\n",
           sessionid, cap_hex);

    err = 0;

out_err:
    cpn_channel_close(&channel);
    cpn_cap_free(cap);
    free(cap_hex);
    if (params)
        protobuf_c_message_free_unpacked(params, NULL);

    return err;
}

static int cmd_connect(const char *service_type, uint32_t sessionid,
        const char *capability)
{
    const struct cpn_service_plugin *plugin;
    struct cpn_channel channel;
    struct cpn_session *session = NULL;
    struct cpn_cap *cap = NULL;
    int err = -1;

    channel.fd = -1;

    if (cpn_service_plugin_for_type(&plugin, service_type) < 0) {
        printf("Invalid service plugin %s\n", service_type);
        goto out;
    }

    if (cpn_cap_from_string(&cap, capability) < 0) {
        puts("Invalid capability");
        goto out;
    }

    if (cpn_client_connect(&channel, remote_host, remote_port,
                &local_keys, &remote_key) < 0)
    {
        puts("Could not start connection");
        goto out;
    }

    if (cpn_client_start_session(&session, &channel, sessionid, cap, plugin) < 0) {
        puts("Could not connect to session");
        goto out;
    }

    if (plugin->client_fn(&channel, session, &cfg) < 0) {
        puts("Could not invoke service");
        goto out;
    }

    err = 0;

out:
    cpn_channel_close(&channel);
    cpn_cap_free(cap);
    cpn_session_free(session);

    return err;
}

static int cmd_terminate(uint32_t sessionid, const char *capability)
{
    struct cpn_channel channel;
    struct cpn_cap *cap = NULL;
    int err = -1;

    if (cpn_cap_from_string(&cap, capability) < 0) {
        puts("Invalid capability\n");
        goto out;
    }

    if (cpn_client_connect(&channel, remote_host, remote_port,
                &local_keys, &remote_key) < 0)
    {
        puts("Could not start connection");
        goto out;
    }

    if (cpn_client_terminate_session(&channel, sessionid, cap) < 0) {
        puts("Could not initiate termination");
        goto out;
    }

    err = 0;

out:
    cpn_cap_free(cap);
    return err;
}

int main(int argc, const char *argv[])
{
    if (cpn_global_init() < 0)
        return -1;

    if (cpn_opts_parse_cmd(opts, argc, argv) < 0) {
        return -1;
    }

    switch (cpn_opts_get(opts, 'v', NULL)->counter) {
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

    if (cpn_cfg_parse(&cfg, cpn_opts_get(opts, 'c', NULL)->string) < 0) {
        printf("Could not parse config '%s", cpn_opts_get(opts, 'c', NULL)->string);
        return -1;
    }

    if (cpn_sign_key_pair_from_config(&local_keys, &cfg) < 0) {
        puts("Could not keys from config");
        return -1;
    }

    memcpy(&remote_key, &cpn_opts_get(opts, 0, "--remote-key")->sigkey, sizeof(struct cpn_sign_key_public));
    remote_host = cpn_opts_get(opts, 0, "--remote-host")->string;
    remote_port = cpn_opts_get(opts, 0, "--remote-port")->uint32;

    if (cpn_opts_get(opts, 0, "query"))
        return cmd_query();
    else if (cpn_opts_get(opts, 0, "request"))
        return cmd_request(cpn_opts_get(request_opts, 0, "--service-type")->string,
                &cpn_opts_get(request_opts, 0, "--parameters")->stringlist);
    else if (cpn_opts_get(opts, 0, "connect"))
        return cmd_connect(cpn_opts_get(connect_opts, 0, "--service-type")->string,
               cpn_opts_get(connect_opts, 0, "--session-id")->uint32,
               cpn_opts_get(connect_opts, 0, "--session-cap")->string);
    else if (cpn_opts_get(opts, 0, "terminate"))
        return cmd_terminate(cpn_opts_get(terminate_opts, 0, "--session-id")->uint32,
                cpn_opts_get(terminate_opts, 0, "--session-cap")->string);
    else
        puts("No action specified");

    return 0;
}
