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

#include <string.h>

#include "capone/channel.h"
#include "capone/cfg.h"
#include "capone/common.h"
#include "capone/service.h"

#include "capone/proto/capabilities.pb-c.h"

#include "test.h"

struct handler_opts {
    struct cpn_channel *channel;
    CapabilitiesParams *params;
};

static const struct cpn_service_plugin *service;
static struct cpn_cfg cfg;
static struct cpn_channel client;
static struct cpn_channel server;
static struct cpn_sign_key_public pk;

static int setup()
{
    assert_success(cpn_sign_key_public_from_hex(&pk, PK));
    assert_success(cpn_cfg_parse_string(&cfg, CFG, strlen(CFG)));
    stub_sockets(&client, &server, CPN_CHANNEL_TYPE_TCP);
    return 0;
}

static int teardown()
{
    cpn_channel_close(&client);
    cpn_channel_close(&server);
    return 0;
}

static void *registrant(void *ignored)
{
    const char *args[] = { "register" };
    UNUSED(ignored);
    service->client_fn(&client, ARRAY_SIZE(args), args, &cfg);
    return NULL;
}

static void *handler(void *payload)
{
    struct handler_opts *opts = (struct handler_opts *) payload;
    struct cpn_session session;
    struct cpn_channel c;

    memcpy(&c, opts->channel, sizeof(c));
    session.parameters = &opts->params->base;
    memcpy(&session.creator, &pk, sizeof(pk));

    service->server_fn(&c, &pk, &session, &cfg);
    return NULL;
}

static void registration_succeeds()
{
    CapabilitiesCommand cmd = CAPABILITIES_COMMAND__INIT;
    struct cpn_thread t;

    cmd.cmd = CAPABILITIES_COMMAND__COMMAND__TERMINATE;

    assert_success(cpn_spawn(&t, registrant, NULL));
    assert_success(cpn_channel_write_protobuf(&server, &cmd.base));
    assert_success(cpn_join(&t, NULL));
}

static void forwarding_request_succeeds()
{
    CapabilitiesParams params = CAPABILITIES_COMMAND__INIT;
    CapabilitiesParams__RequestParams requestParams = CAPABILITIES_PARAMS__REQUEST_PARAMS__INIT;
    CapabilitiesCommand *cmd;
    struct cpn_thread t;
    struct handler_opts opts;

    opts.channel = &server;
    opts.params = &params;

    /* Register with the service */
    params.type = CAPABILITIES_PARAMS__TYPE__REGISTER;
    assert_success(cpn_spawn(&t, handler, &opts));
    assert_success(cpn_join(&t, NULL));

    requestParams.service_address = "localhost";
    requestParams.service_port = "12345";
    requestParams.service_type = "test";
    assert_success(cpn_sign_key_public_to_proto(&requestParams.requested_identity, &pk));
    assert_success(cpn_sign_key_public_to_proto(&requestParams.service_identity, &pk));
    params.request_params = &requestParams;
    params.type = CAPABILITIES_PARAMS__TYPE__REQUEST;

    assert_success(cpn_spawn(&t, handler, &opts));
    assert_success(cpn_channel_receive_protobuf(&client, &capabilities_command__descriptor,
            (ProtobufCMessage **) &cmd));
    assert_success(cpn_join(&t, NULL));

    assert_int_equal(cmd->cmd, CAPABILITIES_COMMAND__COMMAND__REQUEST);
    assert_string_equal(cmd->request->service_address, requestParams.service_address);
    assert_string_equal(cmd->request->service_port, requestParams.service_port);
    assert_string_equal(cmd->request->service_type, requestParams.service_type);
    assert_memory_equal(cmd->request->service_identity->data.data, pk.data, sizeof(pk.data));
    assert_memory_equal(cmd->request->requester_identity->data.data, pk.data, sizeof(pk.data));
}

static void parsing_register_succeeds()
{
    const char *args[] = { "register" };
    CapabilitiesParams *params;

    assert_success(service->parse_fn((ProtobufCMessage **) &params, ARRAY_SIZE(args), args));
    assert_true(protobuf_c_message_check(&params->base));
    assert_null(params->request_params);
    assert_int_equal(params->type, CAPABILITIES_PARAMS__TYPE__REGISTER);
}

static void parsing_request_succeeds()
{
    const char *args[] = {
        "request",
        "--requested-identity", PK,
        "--service-identity", PK,
        "--service-address", "localhost",
        "--service-port", "12345",
        "--service-type", "test",
        "--service-parameters", "xvlc",
    };
    CapabilitiesParams *params;

    assert_success(service->parse_fn((ProtobufCMessage **) &params, ARRAY_SIZE(args), args));
    assert_true(protobuf_c_message_check(&params->base));
    assert_int_equal(params->type, CAPABILITIES_PARAMS__TYPE__REQUEST);

    assert_memory_equal(params->request_params->requested_identity->data.data, pk.data, sizeof(pk.data));
    assert_memory_equal(params->request_params->service_identity->data.data, pk.data, sizeof(pk.data));
    assert_string_equal(params->request_params->service_address, "localhost");
    assert_string_equal(params->request_params->service_port, "12345");
    assert_string_equal(params->request_params->service_type, "test");
    assert_int_equal(params->request_params->n_parameters, 1);
    assert_string_equal(params->request_params->parameters[0], "xvlc");

    capabilities_params__free_unpacked(params, NULL);
}

int capabilities_service_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(registration_succeeds),
        test(forwarding_request_succeeds),

        test(parsing_register_succeeds),
        test(parsing_request_succeeds)
    };

    assert_success(cpn_service_plugin_for_type(&service, "capabilities"));

    return execute_test_suite("capabilities-service", tests, NULL, NULL);
}