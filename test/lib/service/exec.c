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

#include "capone/common.h"
#include "capone/channel.h"
#include "capone/service.h"
#include "capone/proto/exec.pb-c.h"

#include "test.h"

#define TEXT "abc\ndef\nuvw\nxyz\n"

struct serve_opts {
    struct cpn_session session;
};

static struct cpn_channel client;
static struct cpn_channel server;
static struct cpn_sign_pk pk;
static struct cpn_cfg cfg;

static const struct cpn_service_plugin *service;

static int setup()
{
    stub_sockets(&client, &server, CPN_CHANNEL_TYPE_TCP);
    return 0;
}

static int teardown()
{
    cpn_channel_close(&client);
    cpn_channel_close(&server);
    return 0;
}

static void *serve(void *payload)
{
    struct serve_opts *opts = (struct serve_opts *) payload;

    assert_success(service->server_fn(&server, &pk, &opts->session, &cfg));
    shutdown(server.fd, SHUT_RDWR);

    return NULL;
}

static void assert_output_equal(const char *cmd, int argc, const char **argv, const char *expected)
{
    ExecParams params = EXEC_PARAMS__INIT;
    struct serve_opts opts;
    struct cpn_thread t;
    uint8_t buf[4096] = { 0 };
    int received, total = 0;

    params.command = (char *) cmd;
    params.arguments = (char **) argv;
    params.n_arguments = argc;

    opts.session.parameters = &params.base;

    assert_success(cpn_spawn(&t, serve, &opts));
    while ((received = cpn_channel_receive_data(&client, buf + total, sizeof(buf) - total)) > 0)
        total += received;
    assert_success(cpn_join(&t, NULL));
    assert_int_equal(total, strlen(expected));
    assert_string_equal(buf, expected);
}

static void capturing_stdout_succeeds()
{
#ifdef MSYS
    skip();
#endif
    assert_output_equal(TEST_HELPER_EXECUTABLE, 0, NULL, TEXT);
}

static void capturing_stdout_succeeds_with_parameter()
{
    const char *args[] = { "stdout" };
#ifdef MSYS
    skip();
#endif
    assert_output_equal(TEST_HELPER_EXECUTABLE, ARRAY_SIZE(args), args, TEXT);
}

static void capturing_stdout_succeeds_with_multiple_parameters()
{
    const char *args[] = { "stdout", "ignored" };
#ifdef MSYS
    skip();
#endif
    assert_output_equal(TEST_HELPER_EXECUTABLE, ARRAY_SIZE(args), args, TEXT);
}

static void capturing_command_without_output_succeeds()
{
    const char *args[] = { "nothing" };
#ifdef MSYS
    skip();
#endif
    assert_output_equal(TEST_HELPER_EXECUTABLE, ARRAY_SIZE(args), args, "");
}

static void capturing_stderr_succeeds()
{
    const char *args[] = { "stderr" };
#ifdef MSYS
    skip();
#endif
    assert_output_equal(TEST_HELPER_EXECUTABLE, ARRAY_SIZE(args), args, TEXT);
}

static void capturing_mixed_succeeds()
{
    const char *args[] = { "mixed" };
#ifdef MSYS
    skip();
#endif
    assert_output_equal(TEST_HELPER_EXECUTABLE, ARRAY_SIZE(args), args, TEXT);
}

static void parsing_command_without_args_succeeds()
{
    const char *args[] = { "--command", "test" };
    ExecParams *params;

    assert_success(service->parse_fn((ProtobufCMessage **) &params, ARRAY_SIZE(args), args));
    assert_true(protobuf_c_message_check(&params->base));
    assert_string_equal(params->command, "test");
    assert_int_equal(params->n_arguments, 0);

    exec_params__free_unpacked(params, NULL);
}

static void parsing_command_with_single_arg_succeeds()
{
    const char *args[] = { "--command", "test", "--arguments", "bla" };
    ExecParams *params;

    assert_success(service->parse_fn((ProtobufCMessage **) &params, ARRAY_SIZE(args), args));
    assert_true(protobuf_c_message_check(&params->base));
    assert_string_equal(params->command, "test");
    assert_int_equal(params->n_arguments, 1);
    assert_string_equal(params->arguments[0], "bla");

    exec_params__free_unpacked(params, NULL);
}

static void parsing_command_with_multiple_args_succeeds()
{
    const char *args[] = { "--command", "test", "--arguments", "bla", "uiae" };
    ExecParams *params;

    assert_success(service->parse_fn((ProtobufCMessage **) &params, ARRAY_SIZE(args), args));
    assert_true(protobuf_c_message_check(&params->base));
    assert_string_equal(params->command, "test");
    assert_int_equal(params->n_arguments, 2);
    assert_string_equal(params->arguments[0], "bla");
    assert_string_equal(params->arguments[1], "uiae");

    exec_params__free_unpacked(params, NULL);
}

static void parsing_command_with_invalid_args_fails()
{
    const char *args[] = { "--cmand", "test", "--arguments", "bla", "uiae" };
    ExecParams *params = NULL;

    assert_failure(service->parse_fn((ProtobufCMessage **) &params, ARRAY_SIZE(args), args));
    assert_null(params);
}

int exec_service_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(capturing_stdout_succeeds),
        test(capturing_command_without_output_succeeds),
        test(capturing_stdout_succeeds_with_parameter),
        test(capturing_stdout_succeeds_with_multiple_parameters),
        test(capturing_stderr_succeeds),
        test(capturing_mixed_succeeds),

        test(parsing_command_without_args_succeeds),
        test(parsing_command_with_single_arg_succeeds),
        test(parsing_command_with_multiple_args_succeeds),
        test(parsing_command_with_invalid_args_fails)
    };

    assert_success(cpn_service_plugin_for_type(&service, "exec"));

    return execute_test_suite("exec-service", tests, NULL, NULL);
}
