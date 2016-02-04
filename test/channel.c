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

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include "lib/channel.h"

static struct sd_channel channel;

static int setup()
{
    sd_channel_init(&channel);
    return 0;
}

static int teardown()
{
    sd_channel_close(&channel);
    return 0;
}

static void initialization_sets_invalid_sockets()
{
    channel.local_fd = 123;
    sd_channel_init(&channel);

    assert_int_equal(channel.local_fd, -1);
    assert_int_equal(channel.remote_fd, -1);
}

static void close_resets_sockets_to_invalid_values()
{
    channel.local_fd = INT_MAX;;
    channel.remote_fd = INT_MAX;;

    sd_channel_close(&channel);

    assert_int_equal(channel.local_fd, -1);
    assert_int_equal(channel.remote_fd, -1);
}

static void set_local_address_to_localhost()
{
    assert_int_equal(sd_channel_set_local_address(&channel,
                "localhost", "8080", SD_CHANNEL_TYPE_TCP), 0);
    assert_true(channel.local_fd >= 0);
}

static void set_local_address_to_127001()
{
    assert_int_equal(sd_channel_set_local_address(&channel,
                "127.0.0.1", "8080", SD_CHANNEL_TYPE_TCP), 0);
    assert_true(channel.local_fd >= 0);
}

static void set_local_address_to_empty_address()
{
    assert_int_equal(sd_channel_set_local_address(&channel,
                NULL, "8080", SD_CHANNEL_TYPE_TCP), 0);
    assert_true(channel.local_fd >= 0);
}

static void set_local_address_to_invalid_address()
{
    assert_int_equal(sd_channel_set_local_address(&channel,
                "999.999.999.999", "8080", SD_CHANNEL_TYPE_TCP), -1);
    assert_true(channel.local_fd >= 0);
}

static void set_remote_address_to_localhost()
{
    assert_int_equal(sd_channel_set_remote_address(&channel,
                "localhost", "8080", SD_CHANNEL_TYPE_TCP), 0);
    assert_true(channel.local_fd >= 0);
}

static void set_remote_address_to_127001()
{
    assert_int_equal(sd_channel_set_remote_address(&channel,
                "127.0.0.1", "8080", SD_CHANNEL_TYPE_TCP), 0);
    assert_true(channel.local_fd >= 0);
}

static void set_remote_address_to_empty_address()
{
    assert_int_equal(sd_channel_set_remote_address(&channel,
                NULL, "8080", SD_CHANNEL_TYPE_TCP), 0);
    assert_true(channel.local_fd >= 0);
}

static void set_remote_address_to_invalid_address()
{
    assert_int_equal(sd_channel_set_remote_address(&channel,
                "999.999.999.999", "8080", SD_CHANNEL_TYPE_TCP), -1);
    assert_true(channel.local_fd >= 0);
}

static void connect_fails_without_other_side()
{
    assert_int_equal(sd_channel_set_remote_address(&channel,
                "127.0.0.1", "8080", SD_CHANNEL_TYPE_TCP), 0);
    assert_int_equal(sd_channel_connect(&channel), -1);
}

int channel_test_run_suite()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(initialization_sets_invalid_sockets),
        cmocka_unit_test(close_resets_sockets_to_invalid_values),

        cmocka_unit_test(set_local_address_to_localhost),
        cmocka_unit_test(set_local_address_to_127001),
        cmocka_unit_test(set_local_address_to_empty_address),
        cmocka_unit_test(set_local_address_to_invalid_address),

        cmocka_unit_test(set_remote_address_to_localhost),
        cmocka_unit_test(set_remote_address_to_127001),
        cmocka_unit_test(set_remote_address_to_empty_address),
        cmocka_unit_test(set_remote_address_to_invalid_address),

        cmocka_unit_test(connect_fails_without_other_side),
    };

    return cmocka_run_group_tests_name("channel", tests, setup, teardown);
}

