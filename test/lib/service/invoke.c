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
#include "capone/common.h"
#include "capone/server.h"
#include "capone/service.h"
#include "capone/socket.h"

#include "capone/proto/connect.pb-c.h"
#include "capone/proto/invoke.pb-c.h"

#include "test.h"
#include "../test-service.h"

#define PORT "23489"

struct invoker_opts {
    struct cpn_session session;
    struct cpn_channel *channel;
};

static struct cpn_cfg cfg;

static struct cpn_sign_key_pair keys;
static SignatureKey *key_proto;

static struct cpn_cap cap;
static CapabilityMessage *cap_proto;

static const struct cpn_service_plugin *service;

static int setup()
{
    assert_success(cpn_cfg_parse_string(&cfg, CFG, strlen(CFG)));
    assert_success(cpn_sign_key_pair_from_config(&keys, &cfg));
    assert_success(cpn_service_plugin_for_type(&service, "invoke"));

    assert_success(cpn_sign_key_public_to_proto(&key_proto, &keys.pk));
    assert_success(cpn_cap_to_protobuf(&cap_proto, &cap));

    return 0;
}

static int teardown()
{
    cpn_cfg_free(&cfg);

    signature_key__free_unpacked(key_proto, NULL);
    capability_message__free_unpacked(cap_proto, NULL);

    return 0;
}

static void *invoker(void *payload)
{
    struct invoker_opts *opts = (struct invoker_opts *) payload;
    service->server_fn(opts->channel, &keys.pk, &opts->session, &cfg);
    return NULL;
}

static void invoking_succeeds()
{
    InvokeParams params = INVOKE_PARAMS__INIT;
    SessionResult result = SESSION_RESULT__INIT;
    SessionInitiationMessage *msg;
    struct invoker_opts opts;
    struct cpn_socket socket;
    struct cpn_channel c;
    struct cpn_thread t;
    enum cpn_command type;

    assert_success(cpn_socket_init(&socket, "127.0.0.1", "8080", CPN_CHANNEL_TYPE_TCP));
    assert_success(cpn_socket_listen(&socket));

    params.sessionid = 12345;
    params.service_address = "127.0.0.1";
    params.service_port = "8080";
    params.service_type = "test";
    params.service_identity = key_proto;
    params.cap = cap_proto;

    opts.session.parameters = &params.base;

    assert_success(cpn_spawn(&t, invoker, &opts));

    assert_success(cpn_socket_accept(&socket, &c));
    assert_success(cpn_server_await_encryption(&c, &keys, &keys.pk));
    assert_success(cpn_server_await_command(&type, &c));
    assert_int_equal(type, CPN_COMMAND_CONNECT);
    assert_success(cpn_channel_receive_protobuf(&c, &session_initiation_message__descriptor,
                (ProtobufCMessage **) &msg));
    result.result = 0;
    assert_success(cpn_channel_write_protobuf(&c, &result.base));
    assert_success(cpn_channel_write_data(&c, (uint8_t *) "test", 5));

    assert_success(service->client_fn(&c, 0, NULL, &cfg));

    assert_success(cpn_join(&t, NULL));
    cpn_channel_close(&c);

    assert_string_equal(cpn_test_service_get_data(), "test");
    assert_int_equal(msg->identifier, 12345);
    assert_int_equal(msg->capability->n_chain, 0);
    assert_null(msg->capability->chain);
    assert_int_equal(msg->capability->secret.len, sizeof(cap.secret));
    assert_memory_equal(msg->capability->secret.data, cap.secret, sizeof(cap.secret));

    session_initiation_message__free_unpacked(msg, NULL);

    cpn_socket_close(&socket);
}

static void invoking_fails_with_invalid_service_type()
{
    InvokeParams params = INVOKE_PARAMS__INIT;
    struct cpn_session session;
    struct cpn_channel c;

    params.sessionid = 12345;
    params.service_address = "localhost";
    params.service_port = PORT;
    params.service_type = "INVALID";
    params.service_identity = key_proto;
    params.cap = cap_proto;

    session.cap = &cap;
    session.identifier = 1;
    session.parameters = &params.base;

    assert_failure(service->server_fn(&c, &keys.pk, &session, &cfg));
}

static void invoking_fails_with_invalid_capability()
{
    InvokeParams params = INVOKE_PARAMS__INIT;
    struct cpn_session session;
    struct cpn_channel c;

    params.sessionid = 12345;
    params.service_address = "localhost";
    params.service_port = PORT;
    params.service_type = "test";
    params.service_identity = key_proto;
    params.cap = cap_proto;
    params.cap->secret.len--;

    session.cap = &cap;
    session.identifier = 1;
    session.parameters = &params.base;

    assert_failure(service->server_fn(&c, &keys.pk, &session, &cfg));
}

static void invoking_fails_with_invalid_service_identity()
{
    InvokeParams params = INVOKE_PARAMS__INIT;
    struct cpn_session session;
    struct cpn_channel c;

    params.sessionid = 12345;
    params.service_address = "localhost";
    params.service_port = PORT;
    params.service_type = "test";
    params.service_identity = key_proto;
    params.service_identity->data.len--;
    params.cap = cap_proto;

    session.cap = &cap;
    session.identifier = 1;
    session.parameters = &params.base;

    assert_failure(service->server_fn(&c, &keys.pk, &session, &cfg));
}

static void parsing_command_succeeds_without_parameters()
{
    const char *args[] = {
        "--sessionid", "12345",
        "--capability", NULL_SECRET "|" PK ":t",
        "--service-identity", PK,
        "--service-address", "localhost",
        "--service-port", "12345",
        "--service-type", "type"
    };
    InvokeParams *params;

    assert_success(service->parse_fn((ProtobufCMessage **) &params, ARRAY_SIZE(args), args));
    assert_true(protobuf_c_message_check(&params->base));
    assert_int_equal(params->sessionid, 12345);
    assert_string_equal(params->service_address, "localhost");
    assert_string_equal(params->service_port, "12345");
    assert_string_equal(params->service_type, "type");
    assert_int_equal(params->n_service_parameters, 0);
    assert_null(params->service_parameters);

    invoke_params__free_unpacked(params, NULL);
}

static void parsing_command_succeeds_with_parameters()
{
    const char *args[] = {
        "--sessionid", "12345",
        "--capability", NULL_SECRET "|" PK ":t",
        "--service-identity", PK,
        "--service-address", "localhost",
        "--service-port", "12345",
        "--service-type", "type",
        "--service-parameters", "a", "b", "c"
    };
    InvokeParams *params;

    assert_success(service->parse_fn((ProtobufCMessage **) &params, ARRAY_SIZE(args), args));
    assert_true(protobuf_c_message_check(&params->base));
    assert_int_equal(params->sessionid, 12345);
    assert_string_equal(params->service_address, "localhost");
    assert_string_equal(params->service_port, "12345");
    assert_string_equal(params->service_type, "type");
    assert_int_equal(params->n_service_parameters, 3);
    assert_string_equal(params->service_parameters[0], "a");
    assert_string_equal(params->service_parameters[1], "b");
    assert_string_equal(params->service_parameters[2], "c");

    invoke_params__free_unpacked(params, NULL);
}

int invoke_service_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(invoking_succeeds),
        test(invoking_fails_with_invalid_service_type),
        test(invoking_fails_with_invalid_capability),
        test(invoking_fails_with_invalid_service_identity),

        test(parsing_command_succeeds_without_parameters),
        test(parsing_command_succeeds_with_parameters)
    };

    return execute_test_suite("invoke-service", tests, NULL, NULL);
}
