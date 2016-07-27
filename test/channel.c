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

#include <sys/types.h>
#include <sys/socket.h>

#include "lib/common.h"
#include "lib/channel.h"

#include "proto/test.pb-c.h"

#include "test.h"

struct relay_args {
    struct cpn_channel *c;
    int fd;
};

static struct cpn_symmetric_key key;
static struct cpn_channel channel, remote;
static enum cpn_channel_type type;

void stub_sockets(struct cpn_channel *local, struct cpn_channel *remote)
{
    int sockets[2];
    struct sockaddr_storage laddr, raddr;
    socklen_t laddrlen = sizeof(laddr), raddrlen = sizeof(raddr);

    switch (local->type) {
        case SD_CHANNEL_TYPE_TCP:
            assert_success(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets));
            break;
        case SD_CHANNEL_TYPE_UDP:
            assert_success(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets));
            break;
    }

    assert_success(getsockname(sockets[0],
                (struct sockaddr *) &laddr, &laddrlen));
    assert_success(getsockname(sockets[1],
                (struct sockaddr *) &raddr, &raddrlen));

    assert_success(cpn_channel_init_from_fd(local, sockets[0], &laddr, laddrlen, local->type));
    assert_success(cpn_channel_init_from_fd(remote, sockets[0], &raddr, raddrlen, remote->type));

    local->fd = sockets[0];
    remote->fd = sockets[1];

}

static int setup()
{
    channel.type = remote.type = type = SD_CHANNEL_TYPE_TCP;
    return 0;
}

static int teardown()
{
    cpn_channel_close(&channel);
    cpn_channel_close(&remote);
    return 0;
}

static void initialization_sets_socket()
{
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));

    cpn_channel_init_from_fd(&channel, 123, &addr, sizeof(addr), type);

    assert_int_equal(channel.fd, 123);
}

static void initialization_sets_type()
{
    channel.type = -1;
    assert_success(cpn_channel_init_from_host(&channel, NULL, "12345", type));
    assert_int_equal(channel.type, type);
}

static void close_resets_sockets_to_invalid_values()
{
    channel.fd = INT_MAX;;

    cpn_channel_close(&channel);

    assert_int_equal(channel.fd, -1);
}

static void init_address_to_localhost()
{
    assert_success(cpn_channel_init_from_host(&channel, "localhost", "8080", type));
    assert_true(channel.fd >= 0);
}

static void init_address_to_127001()
{
    assert_success(cpn_channel_init_from_host(&channel, "127.0.0.1", "8080", type));
    assert_true(channel.fd >= 0);
}

static void init_address_to_empty_address()
{
    assert_success(cpn_channel_init_from_host(&channel, NULL, "8080", type));
    assert_true(channel.fd >= 0);
}

static void init_address_to_invalid_address()
{
    assert_failure(cpn_channel_init_from_host(&channel, "999.999.999.999", "8080", type));
    assert_true(channel.fd < 0);
}

static void write_data()
{
    uint8_t sender[] = "test";
    uint8_t receiver[sizeof(sender)];

    stub_sockets(&channel, &remote);

    assert_success(cpn_channel_write_data(&channel, sender, sizeof(sender)));
    assert_int_equal(cpn_channel_receive_data(&remote, receiver, sizeof(receiver)),
            sizeof(sender));

    assert_string_equal(sender, receiver);
}

static void write_some_data()
{
    uint8_t m[4096];
    uint8_t buf[sizeof(m)];

    memset(m, '1', sizeof(m));
    m[sizeof(m) - 1] = '\0';

    stub_sockets(&channel, &remote);

    assert_success(cpn_channel_write_data(&channel, m, sizeof(m)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m));

    assert_string_equal(m, buf);
}

static void receive_fails_with_too_small_buffer()
{
    uint8_t msg[] = "test",
            buf[sizeof(msg) - 1];

    stub_sockets(&channel, &remote);

    assert_success(cpn_channel_write_data(&channel, msg, sizeof(msg)));
    assert_failure(cpn_channel_receive_data(&remote, buf, sizeof(buf)));
}

static void write_multiple_messages()
{
    uint8_t m1[] = "m1", m2[] = "m2", buf[10];

    stub_sockets(&channel, &remote);

    assert_success(cpn_channel_write_data(&channel, m1, sizeof(m1)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m1));
    assert_string_equal(buf, m1);

    assert_success(cpn_channel_write_data(&channel, m2, sizeof(m2)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m2));
    assert_string_equal(buf, m2);
}

static void write_repeated_before_read()
{
    uint8_t m[] = "m1", buf[10];
    int i;

    stub_sockets(&channel, &remote);

    for (i = 0; i < 10; i++) {
        assert_success(cpn_channel_write_data(&channel, m, sizeof(m)));
    }

    for (i = 0; i < 10; i++) {
        assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m));
    }
}

static void write_with_response()
{
    uint8_t m1[] = "m1", m2[] = "m2", buf[10];

    stub_sockets(&channel, &remote);
    stub_sockets(&remote, &channel);

    assert_success(cpn_channel_write_data(&channel, m1, sizeof(m1)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m1));
    assert_string_equal(buf, m1);

    assert_success(cpn_channel_write_data(&remote, m2, sizeof(m2)));
    assert_int_equal(cpn_channel_receive_data(&channel, buf, sizeof(buf)), sizeof(m2));
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

    assert_success(cpn_channel_write_protobuf(&channel, (ProtobufCMessage *)&msg));
    assert_success(cpn_channel_receive_protobuf(&remote, &test_message__descriptor,
            (ProtobufCMessage **) &recv));

    assert_string_equal(msg.value.data, recv->value.data);

    test_message__free_unpacked(recv, NULL);
}

static void write_encrypted_data()
{
    unsigned char msg[] = "test", buf[sizeof(msg)];

    stub_sockets(&channel, &remote);

    cpn_channel_enable_encryption(&channel, &key, 0);
    cpn_channel_enable_encryption(&remote, &key, 1);

    assert_success(cpn_channel_write_data(&channel, msg, sizeof(msg)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(msg));

    assert_string_equal(msg, buf);
}

static void write_some_encrypted_data()
{
    unsigned char msg[2048], buf[sizeof(msg)];

    memset(msg, 1, sizeof(msg));

    stub_sockets(&channel, &remote);

    cpn_channel_enable_encryption(&channel, &key, 0);
    cpn_channel_enable_encryption(&remote, &key, 1);

    assert_success(cpn_channel_write_data(&channel, msg, sizeof(msg)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(msg));

    assert_memory_equal(msg, buf, sizeof(msg));
}

static void write_multiple_encrypted_messages()
{
    unsigned char m1[] = "test", m2[] = "somewhatlongermessage",
                  buf[sizeof(m2)];

    stub_sockets(&channel, &remote);

    cpn_channel_enable_encryption(&channel, &key, 0);
    cpn_channel_enable_encryption(&remote, &key, 1);

    assert_success(cpn_channel_write_data(&channel, m1, sizeof(m1)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m1));
    assert_string_equal(m1, buf);

    assert_success(cpn_channel_write_data(&channel, m2, sizeof(m2)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m2));
    assert_string_equal(m2, buf);
}

static void write_encrypted_messages_increments_nonce()
{
    unsigned char m1[] = "test", m2[] = "somewhatlongermessage",
                  buf[sizeof(m2)];
    uint8_t nonce[crypto_box_MACBYTES];

    stub_sockets(&channel, &remote);

    cpn_channel_enable_encryption(&channel, &key, 0);
    cpn_channel_enable_encryption(&remote, &key, 1);

    memcpy(nonce, channel.local_nonce, sizeof(nonce));
    assert_success(cpn_channel_write_data(&channel, m1, sizeof(m1)));
    assert_int_not_equal(sodium_compare(nonce, channel.local_nonce, sizeof(nonce)), 0);

    memcpy(nonce, channel.local_nonce, sizeof(nonce));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m1));
    assert_int_not_equal(sodium_compare(nonce, channel.remote_nonce, sizeof(nonce)), 0);
    assert_string_equal(m1, buf);

    assert_success(cpn_channel_write_data(&channel, m2, sizeof(m2)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m2));
    assert_string_equal(m2, buf);
}

static void write_encrypted_message_with_response()
{
    unsigned char m1[] = "test", m2[] = "response",
                  buf[sizeof(m2)];

    stub_sockets(&channel, &remote);

    cpn_channel_enable_encryption(&channel, &key, 0);
    cpn_channel_enable_encryption(&remote, &key, 1);

    assert_success(cpn_channel_write_data(&channel, m1, sizeof(m1)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m1));
    assert_string_equal(m1, buf);

    assert_success(cpn_channel_write_data(&remote, m2, sizeof(m2)));
    assert_int_equal(cpn_channel_receive_data(&channel, buf, sizeof(buf)), sizeof(m2));
    assert_string_equal(m2, buf);
}

static void write_encrypted_message_with_invalid_nonces_fails()
{
    unsigned char m[] = "test", buf[sizeof(m)];

    stub_sockets(&channel, &remote);

    cpn_channel_enable_encryption(&channel, &key, 0);
    cpn_channel_enable_encryption(&remote, &key, 0);

    assert_success(cpn_channel_write_data(&channel, m, sizeof(m)));
    assert_failure(cpn_channel_receive_data(&remote, buf, sizeof(buf)));
}

static void connect_fails_without_other_side()
{
    assert_success(cpn_channel_init_from_host(&channel, "127.0.0.1", "8080", type));
    assert_failure(cpn_channel_connect(&channel));
}

static void *relay_fn(void *payload)
{
    struct relay_args *args = (struct relay_args *) payload;

    cpn_channel_relay(args->c, 1, args->fd);

    return NULL;
}

static void relaying_data_to_socket_succeeds()
{
    uint8_t data[] = "bla", buf[sizeof(data)];
    struct cpn_channel c1, c2, r1, r2;
    struct cpn_thread thread;
    struct relay_args args;

    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));
    memset(&r1, 0, sizeof(r1));
    memset(&r2, 0, sizeof(r2));

    c1.type = c2.type = r1.type = r2.type = type;

    stub_sockets(&c1, &r1);
    stub_sockets(&c2, &r2);

    args.c = &r1;
    args.fd = c2.fd;

    assert_success(cpn_spawn(&thread, relay_fn, &args));

    assert_success(cpn_channel_write_data(&c1, data, sizeof(data)));
    assert_int_equal(recv(r2.fd, buf, sizeof(buf), 0), sizeof(data));
    assert_string_equal(data, buf);

    shutdown(c1.fd, SHUT_RDWR);
    shutdown(c2.fd, SHUT_RDWR);
    shutdown(r1.fd, SHUT_RDWR);
    shutdown(r2.fd, SHUT_RDWR);

    assert_success(cpn_join(&thread, NULL));
}

static void relaying_data_to_channel_succeeds()
{
    uint8_t data[] = "bla", buf[sizeof(data)];
    struct cpn_channel c1, c2, r1, r2;
    struct cpn_thread thread;
    struct relay_args args;

    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));
    memset(&r1, 0, sizeof(r1));
    memset(&r2, 0, sizeof(r2));

    c1.type = c2.type = r1.type = r2.type = type;

    stub_sockets(&c1, &r1);
    stub_sockets(&c2, &r2);

    args.c = &c2;
    args.fd = r1.fd;

    assert_success(cpn_spawn(&thread, relay_fn, &args));

    assert_int_equal(send(c1.fd, data, sizeof(data), 0), sizeof(data));
    assert_int_equal(cpn_channel_receive_data(&r2, buf, sizeof(buf)), sizeof(data));
    assert_string_equal(data, buf);

    shutdown(c1.fd, SHUT_RDWR);
    shutdown(c2.fd, SHUT_RDWR);
    shutdown(r1.fd, SHUT_RDWR);
    shutdown(r2.fd, SHUT_RDWR);

    assert_success(cpn_join(&thread, NULL));
}

int channel_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(initialization_sets_socket),
        test(initialization_sets_type),
        test(close_resets_sockets_to_invalid_values),

        test(init_address_to_localhost),
        test(init_address_to_127001),
        test(init_address_to_empty_address),
        test(init_address_to_invalid_address),

        test(write_data),
        test(write_some_data),
        test(receive_fails_with_too_small_buffer),
        test(write_multiple_messages),
        test(write_repeated_before_read),
        test(write_with_response),
        test(write_protobuf),
        test(write_encrypted_data),
        test(write_some_encrypted_data),
        test(write_multiple_encrypted_messages),
        test(write_encrypted_messages_increments_nonce),
        test(write_encrypted_message_with_response),
        test(write_encrypted_message_with_invalid_nonces_fails),
        test(connect_fails_without_other_side),

        test(relaying_data_to_socket_succeeds),
        test(relaying_data_to_channel_succeeds)
    };

    cpn_symmetric_key_generate(&key);

    return execute_test_suite("channel", tests, setup, teardown);
}
