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

#include "capone/common.h"
#include "capone/channel.h"

#include "test.h"
#include "lib/test.pb-c.h"

struct relay_args {
    struct cpn_channel *c;
    int nfds;
    int *fds;
};

static struct cpn_symmetric_key key;
static struct cpn_channel channel, remote;

static int setup()
{
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

    cpn_channel_init_from_fd(&channel, 123, (struct sockaddr *) &addr, sizeof(addr), CPN_CHANNEL_TYPE_TCP);

    assert_int_equal(channel.fd, 123);
}

static void initialization_sets_type()
{
    channel.type = -1;
    assert_success(cpn_channel_init_from_host(&channel, NULL, 12345, CPN_CHANNEL_TYPE_TCP));
    assert_int_equal(channel.type, CPN_CHANNEL_TYPE_TCP);
}

static void close_resets_sockets_to_invalid_values()
{
    channel.fd = INT_MAX;;

    cpn_channel_close(&channel);

    assert_int_equal(channel.fd, -1);
}

static void init_address_to_localhost()
{
    assert_success(cpn_channel_init_from_host(&channel, "localhost", 8080, CPN_CHANNEL_TYPE_TCP));
    assert_true(channel.fd >= 0);
}

static void init_address_to_127001()
{
    assert_success(cpn_channel_init_from_host(&channel, "127.0.0.1", 8080, CPN_CHANNEL_TYPE_TCP));
    assert_true(channel.fd >= 0);
}

static void init_address_to_empty_address()
{
    assert_success(cpn_channel_init_from_host(&channel, NULL, 8080, CPN_CHANNEL_TYPE_TCP));
    assert_true(channel.fd >= 0);
}

static void init_address_to_invalid_address()
{
    assert_failure(cpn_channel_init_from_host(&channel, "999.999.999.999", 8080, CPN_CHANNEL_TYPE_TCP));
    assert_true(channel.fd < 0);
}

static void write_data()
{
    uint8_t sender[] = "test";
    uint8_t receiver[sizeof(sender)];

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

    assert_success(cpn_channel_write_data(&channel, sender, sizeof(sender)));
    assert_int_equal(cpn_channel_receive_data(&remote, receiver, sizeof(receiver)),
            sizeof(sender));

    assert_string_equal(sender, receiver);
}

static void write_data_udp()
{
    uint8_t sender[] = "test";
    uint8_t receiver[sizeof(sender)];

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_UDP);

    assert_success(cpn_channel_write_data(&channel, sender, sizeof(sender)));
    assert_int_equal(cpn_channel_receive_data(&remote, receiver, sizeof(receiver)),
            sizeof(sender));

    assert_string_equal(sender, receiver);
}

static void write_data_with_different_block_lengths()
{
    size_t lengths[] = { 64, 128, 512, 1024, 2048 };
    uint8_t sender[] = "test";
    uint8_t receiver[sizeof(sender)];
    uint8_t i;

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

    for (i = 0; i < ARRAY_SIZE(lengths); i++) {
        cpn_channel_set_blocklen(&channel, lengths[i]);
        cpn_channel_set_blocklen(&remote, lengths[i]);

        assert_success(cpn_channel_write_data(&channel, sender, sizeof(sender)));
        assert_int_equal(cpn_channel_receive_data(&remote, receiver, sizeof(receiver)),
                sizeof(sender));
        assert_string_equal(sender, receiver);
    }
}

static void write_some_data()
{
    uint8_t m[4096];
    uint8_t buf[sizeof(m)];

    memset(m, '1', sizeof(m));
    m[sizeof(m) - 1] = '\0';

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

    assert_success(cpn_channel_write_data(&channel, m, sizeof(m)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m));

    assert_string_equal(m, buf);
}

static void write_some_data_udp()
{
    uint8_t m[4096];
    uint8_t buf[sizeof(m)];

    memset(m, '1', sizeof(m));
    m[sizeof(m) - 1] = '\0';

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_UDP);

    assert_success(cpn_channel_write_data(&channel, m, sizeof(m)));
    assert_int_equal(cpn_channel_receive_data(&remote, buf, sizeof(buf)), sizeof(m));

    assert_string_equal(m, buf);
}


static void receive_fails_with_too_small_buffer()
{
    uint8_t msg[] = "test",
            buf[sizeof(msg) - 1];

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

    assert_success(cpn_channel_write_data(&channel, msg, sizeof(msg)));
    assert_failure(cpn_channel_receive_data(&remote, buf, sizeof(buf)));
}

static void write_multiple_messages()
{
    uint8_t m1[] = "m1", m2[] = "m2", buf[10];

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

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

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

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

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

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
    char value[] = "test";

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

    test_message__init(&msg);
    msg.value = value;

    assert_success(cpn_channel_write_protobuf(&channel, (ProtobufCMessage *)&msg));
    assert_success(cpn_channel_receive_protobuf(&remote, &test_message__descriptor,
            (ProtobufCMessage **) &recv));

    assert_string_equal(msg.value, recv->value);

    test_message__free_unpacked(recv, NULL);
}

static void write_encrypted_data()
{
    unsigned char msg[] = "test", buf[sizeof(msg)];

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

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

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

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

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

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

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

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

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

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

    stub_sockets(&channel, &remote, CPN_CHANNEL_TYPE_TCP);

    cpn_channel_enable_encryption(&channel, &key, 0);
    cpn_channel_enable_encryption(&remote, &key, 0);

    assert_success(cpn_channel_write_data(&channel, m, sizeof(m)));
    assert_failure(cpn_channel_receive_data(&remote, buf, sizeof(buf)));
}

static void connect_fails_without_other_side()
{
    assert_success(cpn_channel_init_from_host(&channel, "127.0.0.1", 8080, CPN_CHANNEL_TYPE_TCP));
    assert_failure(cpn_channel_connect(&channel));
}

static void *relay_fn(void *payload)
{
    struct relay_args *args = (struct relay_args *) payload;

    switch (args->nfds) {
        case 1:
            cpn_channel_relay(args->c, 1, args->fds[0]);
            break;
        case 2:
            cpn_channel_relay(args->c, 2, args->fds[0], args->fds[1]);
            break;
    }

    return NULL;
}

static void relaying_data_to_socket_succeeds()
{
    uint8_t data[] = "bla", buf[sizeof(data)];
    struct cpn_channel c1, c2, r1, r2;
    struct cpn_thread thread;
    struct relay_args args;
    int fds[1];

    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));
    memset(&r1, 0, sizeof(r1));
    memset(&r2, 0, sizeof(r2));

    stub_sockets(&c1, &r1, CPN_CHANNEL_TYPE_TCP);
    stub_sockets(&c2, &r2, CPN_CHANNEL_TYPE_TCP);

    fds[0] = c2.fd;
    args.c = &r1;
    args.nfds = ARRAY_SIZE(fds);
    args.fds = fds;

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
    int fds[1];

    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));
    memset(&r1, 0, sizeof(r1));
    memset(&r2, 0, sizeof(r2));

    stub_sockets(&c1, &r1, CPN_CHANNEL_TYPE_TCP);
    stub_sockets(&c2, &r2, CPN_CHANNEL_TYPE_TCP);

    fds[0] = r1.fd;

    args.c = &c2;
    args.nfds = ARRAY_SIZE(fds);
    args.fds = fds;

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

static void relaying_multiple_sockets_succeeds()
{
    uint8_t data[] = "bla", buf[sizeof(data)];
    struct cpn_channel c1, c2, c3, r1, r2, r3;
    struct cpn_thread thread;
    struct relay_args args;
    int fds[2];

    stub_sockets(&c1, &r1, CPN_CHANNEL_TYPE_TCP);
    stub_sockets(&c2, &r2, CPN_CHANNEL_TYPE_TCP);
    stub_sockets(&c3, &r3, CPN_CHANNEL_TYPE_TCP);

    fds[0] = r2.fd;
    fds[1] = r3.fd;

    args.c = &c1;
    args.nfds = ARRAY_SIZE(fds);
    args.fds = fds;

    assert_success(cpn_spawn(&thread, relay_fn, &args));

    assert_int_equal(send(c2.fd, data, sizeof(data), 0), sizeof(data));
    assert_int_equal(cpn_channel_receive_data(&r1, buf, sizeof(buf)), sizeof(data));
    assert_string_equal(buf, data);
    assert_int_equal(send(c3.fd, data, sizeof(data), 0), sizeof(data));
    assert_int_equal(cpn_channel_receive_data(&r1, buf, sizeof(buf)), sizeof(data));
    assert_string_equal(buf, data);

    shutdown(c1.fd, SHUT_RDWR);
    shutdown(c2.fd, SHUT_RDWR);
    shutdown(c3.fd, SHUT_RDWR);
    shutdown(r1.fd, SHUT_RDWR);
    shutdown(r2.fd, SHUT_RDWR);
    shutdown(r3.fd, SHUT_RDWR);

    assert_success(cpn_join(&thread, NULL));
}

static void relaying_partially_closed_sockets_succeeds()
{
    uint8_t data[] = "bla", buf[sizeof(data)];
    struct cpn_channel c1, c2, c3, r1, r2, r3;
    struct cpn_thread thread;
    struct relay_args args;
    int fds[2];

    stub_sockets(&c1, &r1, CPN_CHANNEL_TYPE_TCP);
    stub_sockets(&c2, &r2, CPN_CHANNEL_TYPE_TCP);
    stub_sockets(&c3, &r3, CPN_CHANNEL_TYPE_TCP);

    fds[0] = r2.fd;
    fds[1] = r3.fd;

    args.c = &c1;
    args.nfds = ARRAY_SIZE(fds);
    args.fds = fds;

    assert_success(cpn_spawn(&thread, relay_fn, &args));

    shutdown(c2.fd, SHUT_RDWR);
    shutdown(r2.fd, SHUT_RDWR);

    assert_int_equal(send(c3.fd, data, sizeof(data), 0), sizeof(data));
    assert_int_equal(cpn_channel_receive_data(&r1, buf, sizeof(buf)), sizeof(data));
    assert_string_equal(buf, data);
    assert_int_equal(send(c3.fd, data, sizeof(data), 0), sizeof(data));
    assert_int_equal(cpn_channel_receive_data(&r1, buf, sizeof(buf)), sizeof(data));
    assert_string_equal(buf, data);

    shutdown(c1.fd, SHUT_RDWR);
    shutdown(c3.fd, SHUT_RDWR);
    shutdown(r1.fd, SHUT_RDWR);
    shutdown(r3.fd, SHUT_RDWR);

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
        test(write_data_udp),
        test(write_data_with_different_block_lengths),
        test(write_some_data),
        test(write_some_data_udp),
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
        test(relaying_data_to_channel_succeeds),
        test(relaying_multiple_sockets_succeeds),
        test(relaying_partially_closed_sockets_succeeds)
    };

    cpn_symmetric_key_generate(&key);

    return execute_test_suite("channel", tests, setup, teardown);
}
