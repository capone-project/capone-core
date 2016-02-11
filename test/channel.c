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

#include <sodium/crypto_box.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include "lib/common.h"
#include "lib/channel.h"

#include "proto/test.pb-c.h"

#include "test.h"
#include "channel.h"

static uint8_t channel_pk[crypto_box_PUBLICKEYBYTES],
               channel_sk[crypto_box_SECRETKEYBYTES],
               remote_pk[crypto_box_PUBLICKEYBYTES],
               remote_sk[crypto_box_SECRETKEYBYTES],
               local_nonce[crypto_box_NONCEBYTES],
               remote_nonce[crypto_box_NONCEBYTES];

static struct sd_channel channel, remote;
static enum sd_channel_type type;

static void stub_sockets(struct sd_channel *local, struct sd_channel *remote)
{
    int sockets[2];
    unsigned int addrlen = sizeof(local->addr);

    switch (local->type) {
        case SD_CHANNEL_TYPE_TCP:
            assert_success(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets));
            break;
        case SD_CHANNEL_TYPE_UDP:
            assert_success(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets));
            break;
    }

    local->fd = sockets[0];
    remote->fd = sockets[1];

    getsockname(sockets[0], (struct sockaddr *) &local->addr, &addrlen);
    getsockname(sockets[1], (struct sockaddr *) &remote->addr, &addrlen);
}

static int setup_tcp()
{
    channel.type = remote.type = type = SD_CHANNEL_TYPE_TCP;
    sd_channel_set_crypto_none(&channel);
    sd_channel_set_crypto_none(&remote);
    channel.nonce_offset = remote.nonce_offset = 2;
    return 0;
}

static int setup_udp()
{
    channel.type = remote.type = type = SD_CHANNEL_TYPE_TCP;
    sd_channel_set_crypto_none(&channel);
    sd_channel_set_crypto_none(&remote);
    channel.nonce_offset = remote.nonce_offset = 2;
    return 0;
}

static int teardown()
{
    sd_channel_close(&channel);
    sd_channel_close(&remote);
    return 0;
}

static void initialization_sets_socket()
{
    struct sockaddr_storage addr;

    sd_channel_init_from_fd(&channel, 123, addr, type);

    assert_int_equal(channel.fd, 123);
}

static void initialization_sets_type()
{
    channel.type = -1;
    assert_success(sd_channel_init_from_host(&channel, NULL, "12345", type));
    assert_int_equal(channel.type, type);
}

static void close_resets_sockets_to_invalid_values()
{
    channel.fd = INT_MAX;;

    sd_channel_close(&channel);

    assert_int_equal(channel.fd, -1);
}

static void init_address_to_localhost()
{
    assert_success(sd_channel_init_from_host(&channel, "localhost", "8080", type));
    assert_true(channel.fd >= 0);
}

static void init_address_to_127001()
{
    assert_success(sd_channel_init_from_host(&channel, "127.0.0.1", "8080", type));
    assert_true(channel.fd >= 0);
}

static void init_address_to_empty_address()
{
    assert_success(sd_channel_init_from_host(&channel, NULL, "8080", type));
    assert_true(channel.fd >= 0);
}

static void init_address_to_invalid_address()
{
    assert_failure(sd_channel_init_from_host(&channel, "999.999.999.999", "8080", type));
    assert_true(channel.fd >= 0);
}

static void write_data()
{
    uint8_t sender[] = "test";
    uint8_t receiver[sizeof(sender)];

    stub_sockets(&channel, &remote);

    assert_success(sd_channel_write_data(&channel, sender, sizeof(sender)));
    assert_int_equal(sd_channel_receive_data(&remote, receiver, sizeof(receiver)),
            sizeof(sender));

    assert_string_equal(sender, receiver);
}

static void receive_fails_with_too_small_buffer()
{
    uint8_t msg[] = "test",
            buf[sizeof(msg) - 1];

    stub_sockets(&channel, &remote);

    assert_success(sd_channel_write_data(&channel, msg, sizeof(msg)));
    assert_failure(sd_channel_receive_data(&remote, buf, sizeof(buf)));
}

static void write_multiple_messages()
{
    uint8_t m1[] = "m1", m2[] = "m2", buf[10];

    stub_sockets(&channel, &remote);

    assert_success(sd_channel_write_data(&channel, m1, sizeof(m1)));
    assert_int_equal(sd_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m1));
    assert_string_equal(buf, m1);

    assert_success(sd_channel_write_data(&channel, m2, sizeof(m2)));
    assert_int_equal(sd_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m2));
    assert_string_equal(buf, m2);
}

static void write_with_response()
{
    uint8_t m1[] = "m1", m2[] = "m2", buf[10];

    stub_sockets(&channel, &remote);
    stub_sockets(&remote, &channel);

    assert_success(sd_channel_write_data(&channel, m1, sizeof(m1)));
    assert_int_equal(sd_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m1));
    assert_string_equal(buf, m1);

    assert_success(sd_channel_write_data(&remote, m2, sizeof(m2)));
    assert_int_equal(sd_channel_receive_data(&channel, buf, sizeof(buf)), sizeof(m2));
    assert_string_equal(buf, m2);
}

static void write_protobuf()
{
    TestMessage msg, *recv = NULL;
    unsigned char value[] = "test";

    stub_sockets(&channel, &remote);

    test_message__init(&msg);
    msg.value.data = value;
    msg.value.len = sizeof(value);

    assert_success(sd_channel_write_protobuf(&channel, (ProtobufCMessage *)&msg));
    assert_success(sd_channel_receive_protobuf(&remote,
            (ProtobufCMessageDescriptor *) &test_message__descriptor,
            (ProtobufCMessage **) &recv));

    assert_string_equal(msg.value.data, recv->value.data);
}

static void write_encrypted_data()
{
    unsigned char msg[] = "test", buf[sizeof(msg)];

    stub_sockets(&channel, &remote);

    sd_channel_set_crypto_encrypt(&channel, channel_pk, channel_sk, remote_pk,
            local_nonce, remote_nonce);
    sd_channel_set_crypto_encrypt(&remote, remote_pk, remote_sk, channel_pk,
            remote_nonce, local_nonce);

    assert_success(sd_channel_write_data(&channel, msg, sizeof(msg)));
    assert_int_equal(sd_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(msg));

    assert_string_equal(msg, buf);
}

static void write_multiple_encrypted_messages()
{
    unsigned char m1[] = "test", m2[] = "somewhatlongermessage",
                  buf[sizeof(m2)];

    stub_sockets(&channel, &remote);

    sd_channel_set_crypto_encrypt(&channel, channel_pk, channel_sk, remote_pk,
            local_nonce, remote_nonce);
    sd_channel_set_crypto_encrypt(&remote, remote_pk, remote_sk, channel_pk,
            remote_nonce, local_nonce);

    assert_success(sd_channel_write_data(&channel, m1, sizeof(m1)));
    assert_int_equal(sd_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m1));
    assert_string_equal(m1, buf);

    assert_success(sd_channel_write_data(&channel, m2, sizeof(m2)));
    assert_int_equal(sd_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m2));
    assert_string_equal(m2, buf);
}

static void write_encrypted_messages_increments_nonce()
{
    unsigned char m1[] = "test", m2[] = "somewhatlongermessage",
                  buf[sizeof(m2)];
    uint8_t nonce[crypto_box_MACBYTES];

    stub_sockets(&channel, &remote);

    sd_channel_set_crypto_encrypt(&channel, channel_pk, channel_sk, remote_pk,
            local_nonce, remote_nonce);
    sd_channel_set_crypto_encrypt(&remote, remote_pk, remote_sk, channel_pk,
            remote_nonce, local_nonce);

    memcpy(nonce, channel.local_nonce, sizeof(nonce));
    assert_success(sd_channel_write_data(&channel, m1, sizeof(m1)));
    assert_int_not_equal(sodium_compare(nonce, channel.local_nonce, sizeof(nonce)), 0);

    memcpy(nonce, channel.local_nonce, sizeof(nonce));
    assert_int_equal(sd_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m1));
    assert_int_not_equal(sodium_compare(nonce, channel.remote_nonce, sizeof(nonce)), 0);
    assert_string_equal(m1, buf);

    assert_success(sd_channel_write_data(&channel, m2, sizeof(m2)));
    assert_int_equal(sd_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m2));
    assert_string_equal(m2, buf);
}

static void write_encrypted_message_with_response()
{
    unsigned char m1[] = "test", m2[] = "response",
                  buf[sizeof(m2)];

    stub_sockets(&channel, &remote);

    sd_channel_set_crypto_encrypt(&channel, channel_pk, channel_sk, remote_pk,
            local_nonce, remote_nonce);
    sd_channel_set_crypto_encrypt(&remote, remote_pk, remote_sk, channel_pk,
            remote_nonce, local_nonce);

    assert_success(sd_channel_write_data(&channel, m1, sizeof(m1)));
    assert_int_equal(sd_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m1));
    assert_string_equal(m1, buf);

    assert_success(sd_channel_write_data(&remote, m2, sizeof(m2)));
    assert_int_equal(sd_channel_receive_data(&channel, buf, sizeof(buf)), sizeof(m2));
    assert_string_equal(m2, buf);
}

static void connect_fails_without_other_side()
{
    assert_success(sd_channel_init_from_host(&channel, "127.0.0.1", "8080", type));
    assert_failure(sd_channel_connect(&channel));
}

int channel_test_run_suite(void)
{
    const struct CMUnitTest shared_tests[] = {
        cmocka_unit_test(initialization_sets_socket),
        cmocka_unit_test(initialization_sets_type),
        cmocka_unit_test(close_resets_sockets_to_invalid_values),

        cmocka_unit_test(init_address_to_localhost),
        cmocka_unit_test(init_address_to_127001),
        cmocka_unit_test(init_address_to_empty_address),
        cmocka_unit_test(init_address_to_invalid_address),
    };
    const struct CMUnitTest tcp_tests[] = {
        cmocka_unit_test(write_data),
        cmocka_unit_test(receive_fails_with_too_small_buffer),
        cmocka_unit_test(write_multiple_messages),
        cmocka_unit_test(write_with_response),
        cmocka_unit_test(write_protobuf),
        cmocka_unit_test(write_encrypted_data),
        cmocka_unit_test(write_multiple_encrypted_messages),
        cmocka_unit_test(write_encrypted_messages_increments_nonce),
        cmocka_unit_test(write_encrypted_message_with_response),
        cmocka_unit_test(connect_fails_without_other_side),
    };

    crypto_box_keypair(channel_pk, channel_sk);
    crypto_box_keypair(remote_pk, remote_sk);
    randombytes(local_nonce, sizeof(local_nonce));
    randombytes(remote_nonce, sizeof(remote_nonce));

    return execute_test_suite("channel_tcp_shared", shared_tests, setup_tcp, teardown) ||
           execute_test_suite("channel_udp_shared", shared_tests, setup_udp, teardown) ||
           execute_test_suite("channel_tcp", tcp_tests, setup_tcp, teardown);
}
