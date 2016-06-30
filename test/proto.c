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

#include "lib/channel.h"
#include "lib/common.h"
#include "lib/proto.h"
#include "lib/server.h"
#include "lib/service.h"
#include "lib/session.h"

#include "service/test.h"

#include "test.h"

extern void stub_sockets(struct sd_channel *local, struct sd_channel *remote);

struct initiate_connection_args {
    enum sd_connection_type type;
};

struct await_encryption_args {
    struct sd_channel *c;
    struct sd_sign_key_pair *k;
};

struct await_query_args {
    struct await_encryption_args enc_args;
    struct sd_service *s;
    struct sd_sign_key_public *r;
    struct sd_sign_key_public *whitelist;
    size_t nwhitelist;
};

struct await_request_args {
    struct await_encryption_args enc_args;
    struct sd_service *s;
    struct sd_sign_key_public *r;
    struct sd_sign_key_public *whitelist;
    size_t nwhitelist;
};

struct handle_session_args {
    struct await_encryption_args enc_args;
    struct sd_sign_key_public *remote_key;
    struct sd_service *service;
    struct sd_cfg *cfg;
};

struct handle_termination_args {
    struct sd_channel *channel;
    struct sd_sign_key_public *terminator;
};

static struct sd_cfg config;
static struct sd_service service;
static struct sd_channel local, remote;
static struct sd_sign_key_pair local_keys, remote_keys;

static int setup()
{
    memset(&local, 0, sizeof(local));
    memset(&remote, 0, sizeof(remote));

    stub_sockets(&local, &remote);
    local.type = remote.type = SD_CHANNEL_TYPE_TCP;
    local.crypto = remote.crypto = SD_CHANNEL_CRYPTO_NONE;

    return 0;
}

static int teardown()
{
    sd_channel_close(&local);
    sd_channel_close(&remote);
    sd_sessions_clear();
    return 0;
}

static void *await_encryption(void *payload)
{
    struct await_encryption_args *args = (struct await_encryption_args *) payload;
    struct sd_sign_key_public remote_key;

    UNUSED(sd_proto_await_encryption(args->c, args->k, &remote_key));

    return NULL;
}

static void *initiate_connection(void *payload)
{
    struct sd_channel c;
    struct initiate_connection_args *args =
        (struct initiate_connection_args *) payload;

    UNUSED(sd_proto_initiate_connection(&c, "127.0.0.1", "31248",
                &local_keys, &remote_keys.pk, args->type));

    UNUSED(sd_channel_close(&c));

    return NULL;
}

static void *await_query(void *payload)
{
    struct await_query_args *args = (struct await_query_args *) payload;

    UNUSED(await_encryption(&args->enc_args));

    UNUSED(sd_proto_answer_query(args->enc_args.c, args->s,
                args->r, args->whitelist, args->nwhitelist));

    return NULL;
}

static void *await_request(void *payload)
{
    struct await_request_args *args = (struct await_request_args *) payload;

    await_encryption(&args->enc_args);

    UNUSED(sd_proto_answer_request(args->enc_args.c,
                args->r, args->whitelist, args->nwhitelist));

    return NULL;
}

static void *handle_session(void *payload)
{
    struct handle_session_args *args = (struct handle_session_args *) payload;

    UNUSED(await_encryption(&args->enc_args));

    UNUSED(sd_proto_handle_session(args->enc_args.c,
                args->remote_key, args->service, args->cfg));

    return NULL;
}

static void *handle_termination(void *payload)
{
    struct handle_termination_args *args = (struct handle_termination_args *) payload;

    UNUSED(sd_proto_handle_termination(args->channel, args->terminator));

    return NULL;
}

static void connection_initiation_succeeds()
{
    struct sd_thread t;
    struct sd_server s;
    struct sd_channel c;
    struct initiate_connection_args args;
    struct sd_sign_key_public key;
    enum sd_connection_type types[] = {
        SD_CONNECTION_TYPE_CONNECT,
        SD_CONNECTION_TYPE_QUERY,
        SD_CONNECTION_TYPE_REQUEST
    };
    enum sd_connection_type type;
    size_t i;

    assert_success(sd_server_init(&s, "127.0.0.1", "31248", SD_CHANNEL_TYPE_TCP));
    assert_success(sd_server_listen(&s));

    for (i = 0; i < ARRAY_SIZE(types); i++) {
        args.type = types[i];

        assert_success(sd_spawn(&t, initiate_connection, &args));
        assert_success(sd_server_accept(&s, &c));
        assert_success(sd_proto_await_encryption(&c, &remote_keys, &key));
        assert_success(sd_proto_receive_connection_type(&type, &c));
        assert_int_equal(type, args.type);

        assert_success(sd_channel_close(&c));
        assert_success(sd_join(&t, NULL));
    }

    assert_success(sd_server_close(&s));
}

static void encryption_initiation_succeeds()
{
    struct sd_thread t;
    struct await_encryption_args args = {
        &remote, &remote_keys
    };

    sd_spawn(&t, await_encryption, &args);
    assert_success(sd_proto_initiate_encryption(&local,
                &local_keys, &remote_keys.pk));
    sd_join(&t, NULL);

    assert(local.crypto == SD_CHANNEL_CRYPTO_SYMMETRIC);
    assert_memory_equal(&local.key, &remote.key, sizeof(local.key));
    assert_memory_equal(local.local_nonce, remote.remote_nonce, sizeof(local.local_nonce));
    assert_memory_equal(local.remote_nonce, remote.local_nonce, sizeof(local.local_nonce));
}

static void encryption_initiation_fails_with_wrong_remote_key()
{
    struct sd_thread t;
    struct await_encryption_args args = {
        &remote, &remote_keys
    };

    sd_spawn(&t, await_encryption, &args);

    assert_failure(sd_proto_initiate_encryption(&local,
                &local_keys, &local_keys.pk));

    shutdown(local.fd, SHUT_RDWR);
    shutdown(remote.fd, SHUT_RDWR);
    sd_join(&t, NULL);
}

static void query_succeeds()
{
    struct sd_thread t;
    struct await_query_args args = {
        { &remote, &remote_keys }, &service, &local_keys.pk, NULL, 0
    };
    struct sd_query_results results;

    sd_spawn(&t, await_query, &args);
    assert_success(sd_proto_initiate_encryption(&local,
                &local_keys, &remote_keys.pk));
    assert_success(sd_proto_send_query(&results, &local));
    sd_join(&t, NULL);

    assert_string_equal(results.name, "Foo");
    assert_string_equal(results.type, "test");
    assert_string_equal(results.category, "Test");
    assert_string_equal(results.location, "Dunno");
    assert_string_equal(results.port, "1234");
    assert_string_equal(results.version, "0.0.1");
    assert_int_equal(results.nparams, 1);
    assert_string_equal(results.params[0].key, "test");

    sd_query_results_free(&results);
}

static void whitelisted_query_succeeds()
{
    struct await_query_args args = {
        { &remote, &remote_keys }, &service, &local_keys.pk, &local_keys.pk, 1
    };
    struct sd_thread t;
    struct sd_query_results results;

    sd_spawn(&t, await_query, &args);
    assert_success(sd_proto_initiate_encryption(&local,
                &local_keys, &remote_keys.pk));
    assert_success(sd_proto_send_query(&results, &local));
    sd_join(&t, NULL);

    sd_query_results_free(&results);
}

static void request_constructs_session()
{
    struct sd_parameter params[] = {
        { "port", "9999" }
    };
    struct await_request_args args = {
        { &remote, &remote_keys }, &service, &local_keys.pk, NULL, 0
    };
    struct sd_cap invoker, requester;
    struct sd_session added;
    struct sd_thread t;

    sd_spawn(&t, await_request, &args);
    assert_success(sd_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_success(sd_proto_send_request(&invoker, &requester, &local, &local_keys.pk, params, ARRAY_SIZE(params)));
    sd_join(&t, NULL);

    assert_success(sd_sessions_remove(&added, invoker.objectid, &local_keys.pk));
    assert_int_equal(invoker.objectid, added.sessionid);
    assert_memory_equal(&local_keys.pk, &added.invoker, sizeof(local_keys.pk));
    assert_memory_equal(&local_keys.pk, &added.issuer, sizeof(local_keys.pk));

    sd_session_free(&added);
}

static void request_without_params_succeeds()
{
    struct await_request_args args = {
        { &remote, &remote_keys }, &service, &local_keys.pk, NULL, 0
    };
    struct sd_cap invoker, requester;
    struct sd_session added;
    struct sd_thread t;

    sd_spawn(&t, await_request, &args);
    assert_success(sd_proto_initiate_encryption(&local, &local_keys, &remote_keys.pk));
    assert_success(sd_proto_send_request(&invoker, &requester, &local, &local_keys.pk, NULL, 0));
    sd_join(&t, NULL);

    assert_success(sd_sessions_remove(&added, invoker.objectid, &local_keys.pk));
    assert_int_equal(invoker.objectid, added.sessionid);
    assert_int_equal(added.nparameters, 0);
    assert_memory_equal(&local_keys.pk, &added.issuer, sizeof(local_keys.pk));
    assert_memory_equal(&local_keys.pk, &added.invoker, sizeof(local_keys.pk));

    sd_session_free(&added);
}

static void whitlisted_request_constructs_session()
{
    struct sd_parameter params[] = {
        { "port", "9999" }
    };
    struct await_request_args args = {
        { &remote, &remote_keys }, &service, &local_keys.pk, &local_keys.pk, 1
    };
    struct sd_session added;
    struct sd_thread t;
    struct sd_cap invoker, requester;

    sd_spawn(&t, await_request, &args);
    assert_success(sd_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_success(sd_proto_send_request(&invoker, &requester, &local, &local_keys.pk, params, ARRAY_SIZE(params)));
    sd_join(&t, NULL);

    assert_success(sd_sessions_remove(&added, invoker.objectid, &local_keys.pk));
    assert_int_equal(invoker.objectid, added.sessionid);
    assert_memory_equal(&local_keys.pk, &added.issuer, sizeof(local_keys.pk));
    assert_memory_equal(&local_keys.pk, &added.invoker, sizeof(local_keys.pk));

    sd_session_free(&added);
}

static void service_connects()
{
    struct sd_parameter params[] = {
        { "data", "parameter-data" }
    };
    struct handle_session_args args = {
        { &remote, &remote_keys }, &local_keys.pk, &service, &config
    };
    struct sd_thread t;
    uint32_t sessionid;
    uint8_t *received;

    sd_spawn(&t, handle_session, &args);

    assert_success(sd_sessions_add(&sessionid, &local_keys.pk, &local_keys.pk,
                params, ARRAY_SIZE(params)));
    assert_success(sd_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_success(sd_proto_initiate_session(&local, sessionid));
    assert_success(service.invoke(&local, 0, NULL) < 0);

    sd_join(&t, NULL);

    received = sd_test_service_get_data();
    assert_string_equal(params[0].value, received);
}

static void connect_refuses_without_session()
{
    struct handle_session_args args = {
        { &remote, &remote_keys }, &local_keys.pk, &service, &config
    };
    struct sd_thread t;

    sd_spawn(&t, handle_session, &args);

    assert_success(sd_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_failure(sd_proto_initiate_session(&local, 1));

    sd_join(&t, NULL);
}

static void termination_kills_session()
{
    struct handle_termination_args args = {
        &remote, &local_keys.pk
    };
    struct sd_thread t;
    uint32_t sessionid;

    sd_spawn(&t, handle_termination, &args);

    assert_success(sd_sessions_add(&sessionid, &local_keys.pk, &remote_keys.pk, NULL, 0));
    assert_success(sd_proto_initiate_termination(&local, sessionid, &remote_keys.pk));

    sd_join(&t, NULL);

    assert_failure(sd_sessions_find(NULL, sessionid, &remote_keys.pk));
}

static void terminating_nonexistent_does_nothing()
{
    struct handle_termination_args args = {
        &remote, &local_keys.pk
    };
    struct sd_thread t;

    sd_spawn(&t, handle_termination, &args);
    assert_success(sd_proto_initiate_termination(&local, 0, &remote_keys.pk));
    sd_join(&t, NULL);
}

int proto_test_run_suite(void)
{
    static const char *service_cfg =
        "[service]\n"
        "name=Foo\n"
        "type=test\n"
        "location=Dunno\n"
        "port=1234\n";

    const struct CMUnitTest tests[] = {
        test(connection_initiation_succeeds),
        test(encryption_initiation_succeeds),
        test(encryption_initiation_fails_with_wrong_remote_key),

        test(query_succeeds),
        test(whitelisted_query_succeeds),

        test(request_constructs_session),
        test(request_without_params_succeeds),
        test(whitlisted_request_constructs_session),

        test(service_connects),
        test(connect_refuses_without_session),

        test(termination_kills_session),
        test(terminating_nonexistent_does_nothing)
    };

    assert_success(sd_sessions_init());

    assert_success(sd_cfg_parse_string(&config, service_cfg, strlen(service_cfg)));
    assert_success(sd_service_from_config(&service, "Foo", &config));

    assert_success(sd_sign_key_pair_generate(&local_keys));
    assert_success(sd_sign_key_pair_generate(&remote_keys));

    return execute_test_suite("proto", tests, setup, teardown);
}
