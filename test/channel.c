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

#include "lib/common.h"
#include "lib/channel.h"

static struct sd_channel channel, remote;
static enum sd_channel_type type;

static void stub_sockets(struct sd_channel *local, struct sd_channel *remote)
{
    int sockets[2];

    switch (local->type) {
        case SD_CHANNEL_TYPE_TCP:
            assert_success(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets));
            break;
        case SD_CHANNEL_TYPE_UDP:
            assert_success(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets));
            break;
    }

    local->remote_fd = sockets[0];
    remote->local_fd = sockets[1];
}

static int setup_tcp()
{
    type = SD_CHANNEL_TYPE_TCP;
    sd_channel_init(&channel);
    sd_channel_init(&remote);
    return 0;
}

static int setup_udp()
{
    type = SD_CHANNEL_TYPE_UDP;
    sd_channel_init(&channel);
    sd_channel_init(&remote);
    return 0;
}

static int teardown()
{
    sd_channel_close(&channel);
    sd_channel_close(&remote);
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
    assert_success(sd_channel_set_local_address(&channel, "localhost", "8080", type));
    assert_true(channel.local_fd >= 0);
}

static void set_local_address_to_127001()
{
    assert_success(sd_channel_set_local_address(&channel, "127.0.0.1", "8080", type));
    assert_true(channel.local_fd >= 0);
}

static void set_local_address_to_empty_address()
{
    assert_success(sd_channel_set_local_address(&channel, NULL, "8080", type));
    assert_true(channel.local_fd >= 0);
}

static void set_local_address_to_invalid_address()
{
    assert_failure(sd_channel_set_local_address(&channel, "999.999.999.999", "8080", type));
    assert_true(channel.local_fd >= 0);
}

static void set_remote_address_to_localhost()
{
    assert_success(sd_channel_set_remote_address(&channel, "localhost", "8080", type));
    assert_true(channel.local_fd >= 0);
}

static void set_remote_address_to_127001()
{
    assert_success(sd_channel_set_remote_address(&channel, "127.0.0.1", "8080", type));
    assert_true(channel.local_fd >= 0);
}

static void set_remote_address_to_empty_address()
{
    assert_success(sd_channel_set_remote_address(&channel, NULL, "8080", type));
    assert_true(channel.local_fd >= 0);
}

static void set_remote_address_to_invalid_address()
{
    assert_failure(sd_channel_set_remote_address(&channel, "999.999.999.999", "8080", type));
    assert_true(channel.local_fd >= 0);
}

static void connect_fails_without_other_side()
{
    assert_success(sd_channel_set_remote_address(&channel, "127.0.0.1", "8080", type));
    assert_failure(sd_channel_connect(&channel));
}

static void connect_with_other_side()
{
    assert_success(sd_channel_set_local_address(&remote, NULL, "8080", type));
    assert_success(sd_channel_listen(&remote));

    assert_success(sd_channel_set_remote_address(&channel, "127.0.0.1", "8080", type));
    assert_success(sd_channel_connect(&channel));

    assert_success(sd_channel_accept(&remote));
}

static void write_data()
{
    uint8_t sender[] = "test";
    uint8_t receiver[sizeof(sender)];

    stub_sockets(&channel, &remote);

    assert_success(sd_channel_write_data(&channel, sender, sizeof(sender)));
    assert_success(sd_channel_receive_data(&remote, receiver, sizeof(receiver)));

    assert_string_equal(sender, receiver);
}

int channel_test_run_suite()
{
    const struct CMUnitTest shared_tests[] = {
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
    };
    const struct CMUnitTest tcp_tests[] = {
        cmocka_unit_test(connect_fails_without_other_side),
        cmocka_unit_test(connect_with_other_side),
        cmocka_unit_test(write_data),
    };

    return execute_test_suite("channel_tcp_shared", shared_tests, setup_tcp, teardown) ||
           execute_test_suite("channel_udp_shared", shared_tests, setup_udp, teardown) ||
           execute_test_suite("channel_tcp", tcp_tests, setup_tcp, teardown);
}

