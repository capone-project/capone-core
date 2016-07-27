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

#include "lib/server.h"

#include "test.h"

static struct cpn_server server;
static struct cpn_channel channel;
static enum cpn_channel_type type;

static int setup()
{
    type = CPN_CHANNEL_TYPE_TCP;
    return 0;
}

static int teardown()
{
    cpn_server_close(&server);
    cpn_channel_close(&channel);
    return 0;
}

static void set_local_address_to_localhost()
{
    assert_success(cpn_server_init(&server, "localhost", "8080", type));
    assert_true(server.fd >= 0);
}

static void set_local_address_to_127001()
{
    assert_success(cpn_server_init(&server, "127.0.0.1", "8080", type));
    assert_true(server.fd >= 0);
}

static void set_local_address_to_empty_address()
{
    assert_success(cpn_server_init(&server, NULL, "8080", type));
    assert_true(server.fd >= 0);
}

static void set_local_address_to_invalid_address()
{
    assert_failure(cpn_server_init(&server, "999.999.999.999", "8080", type));
    assert_true(server.fd < 0);
}

static void connect_to_localhost_succeeds()
{
    struct cpn_channel connected;
    uint8_t data[] = "test";

    assert_success(cpn_server_init(&server, "127.0.0.1", "8080", type));
    if (type == CPN_CHANNEL_TYPE_TCP)
        assert_success(cpn_server_listen(&server));

    assert_success(cpn_channel_init_from_host(&channel, "127.0.0.1", "8080", type));
    assert_success(cpn_channel_connect(&channel));

    assert_success(cpn_server_accept(&server, &connected));

    assert_success(cpn_channel_write_data(&connected, data, sizeof(data)));

    assert_success(cpn_channel_close(&connected));
}

static void getting_address_succeeds()
{
    char host[20], port[10];

    assert_success(cpn_server_init(&server, "localhost", "12345", type));
    assert_success(cpn_server_get_address(&server, host, sizeof(host), port, sizeof(port)));

    assert_string_equal(host, "localhost");
    assert_string_equal(port, "12345");
}

int server_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(set_local_address_to_localhost),
        test(set_local_address_to_127001),
        test(set_local_address_to_empty_address),
        test(set_local_address_to_invalid_address),
        test(connect_to_localhost_succeeds),
        test(getting_address_succeeds)
    };

    return execute_test_suite("server", tests, NULL, NULL);
}
