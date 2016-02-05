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

#include "test.h"

#include "lib/server.h"

static struct sd_server server;
static struct sd_channel channel;
static enum sd_channel_type type;

static int setup()
{
    type = SD_CHANNEL_TYPE_TCP;
    return 0;
}

static int teardown()
{
    sd_server_close(&server);
    sd_channel_close(&channel);
    return 0;
}

static void set_local_address_to_localhost()
{
    assert_success(sd_server_init(&server, "localhost", "8080", type));
    assert_true(server.fd >= 0);
}

static void set_local_address_to_127001()
{
    assert_success(sd_server_init(&server, "127.0.0.1", "8080", type));
    assert_true(server.fd >= 0);
}

static void set_local_address_to_empty_address()
{
    assert_success(sd_server_init(&server, NULL, "8080", type));
    assert_true(server.fd >= 0);
}

static void set_local_address_to_invalid_address()
{
    assert_failure(sd_server_init(&server, "999.999.999.999", "8080", type));
    assert_true(server.fd >= 0);
}

static void connect_with_other_side()
{
    struct sd_channel connected;
    uint8_t data[] = "test";

    assert_success(sd_server_init(&server, NULL, "8080", type));
    if (type == SD_CHANNEL_TYPE_TCP)
        assert_success(sd_server_listen(&server));

    assert_success(sd_channel_init_from_address(&channel, "127.0.0.1", "8080", type));
    assert_success(sd_channel_connect(&channel));

    assert_success(sd_server_accept(&server, &connected));

    assert_success(sd_channel_write_data(&connected, data, sizeof(data)));

    assert_success(sd_channel_close(&connected));
}

int server_test_run_suite()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(set_local_address_to_localhost),
        cmocka_unit_test(set_local_address_to_127001),
        cmocka_unit_test(set_local_address_to_empty_address),
        cmocka_unit_test(set_local_address_to_invalid_address),
        cmocka_unit_test(connect_with_other_side),
    };

    return execute_test_suite("server", tests, setup, teardown);
}
