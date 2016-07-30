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
#include "capone/proto.h"
#include "capone/server.h"
#include "capone/service.h"
#include "capone/session.h"

#include "service/test.h"

#include "test.h"

extern void stub_sockets(struct cpn_channel *local, struct cpn_channel *remote);

struct initiate_connection_args {
    enum cpn_connection_type type;
};

struct await_encryption_args {
    struct cpn_channel *c;
    struct cpn_sign_key_pair *k;
};

struct await_query_args {
    struct await_encryption_args enc_args;
    struct cpn_service *s;
};

struct await_request_args {
    struct await_encryption_args enc_args;
    struct cpn_service *s;
    struct cpn_sign_key_public *r;
    struct cpn_sign_key_public *whitelist;
    size_t nwhitelist;
};

struct handle_session_args {
    struct await_encryption_args enc_args;
    struct cpn_sign_key_public *remote_key;
    struct cpn_service *service;
    struct cpn_cfg *cfg;
};

struct handle_termination_args {
    struct cpn_channel *channel;
    struct cpn_sign_key_public *terminator;
};

static struct cpn_cfg config;
static struct cpn_service service;
static struct cpn_channel local, remote;
static struct cpn_sign_key_pair local_keys, remote_keys;

static int setup()
{
    memset(&local, 0, sizeof(local));
    memset(&remote, 0, sizeof(remote));

    stub_sockets(&local, &remote);
    local.type = remote.type = CPN_CHANNEL_TYPE_TCP;
    local.crypto = remote.crypto = CPN_CHANNEL_CRYPTO_NONE;

    return 0;
}

static int teardown()
{
    cpn_channel_close(&local);
    cpn_channel_close(&remote);
    cpn_sessions_clear();
    cpn_caps_clear();
    return 0;
}

static void *await_encryption(void *payload)
{
    struct await_encryption_args *args = (struct await_encryption_args *) payload;
    struct cpn_sign_key_public remote_key;

    UNUSED(cpn_proto_await_encryption(args->c, args->k, &remote_key));

    return NULL;
}

static void *initiate_connection(void *payload)
{
    struct cpn_channel c;
    struct initiate_connection_args *args =
        (struct initiate_connection_args *) payload;

    UNUSED(cpn_proto_initiate_connection(&c, "127.0.0.1", "31248",
                &local_keys, &remote_keys.pk, args->type));

    UNUSED(cpn_channel_close(&c));

    return NULL;
}

static void *await_query(void *payload)
{
    struct await_query_args *args = (struct await_query_args *) payload;

    UNUSED(await_encryption(&args->enc_args));

    UNUSED(cpn_proto_answer_query(args->enc_args.c, args->s));

    return NULL;
}

static void *await_request(void *payload)
{
    struct await_request_args *args = (struct await_request_args *) payload;

    await_encryption(&args->enc_args);

    UNUSED(cpn_proto_answer_request(args->enc_args.c, args->r));

    return NULL;
}

static void *handle_session(void *payload)
{
    struct handle_session_args *args = (struct handle_session_args *) payload;

    UNUSED(await_encryption(&args->enc_args));

    UNUSED(cpn_proto_handle_session(args->enc_args.c,
                args->remote_key, args->service, args->cfg));

    return NULL;
}

static void *handle_termination(void *payload)
{
    struct handle_termination_args *args = (struct handle_termination_args *) payload;

    UNUSED(cpn_proto_handle_termination(args->channel, args->terminator));

    return NULL;
}

static void connection_initiation_succeeds()
{
    struct cpn_thread t;
    struct cpn_server s;
    struct cpn_channel c;
    struct initiate_connection_args args;
    struct cpn_sign_key_public key;
    enum cpn_connection_type types[] = {
        CPN_CONNECTION_TYPE_CONNECT,
        CPN_CONNECTION_TYPE_QUERY,
        CPN_CONNECTION_TYPE_REQUEST
    };
    enum cpn_connection_type type;
    size_t i;

    assert_success(cpn_server_init(&s, "127.0.0.1", "31248", CPN_CHANNEL_TYPE_TCP));
    assert_success(cpn_server_listen(&s));

    for (i = 0; i < ARRAY_SIZE(types); i++) {
        args.type = types[i];

        assert_success(cpn_spawn(&t, initiate_connection, &args));
        assert_success(cpn_server_accept(&s, &c));
        assert_success(cpn_proto_await_encryption(&c, &remote_keys, &key));
        assert_success(cpn_proto_receive_connection_type(&type, &c));
        assert_int_equal(type, args.type);

        assert_success(cpn_channel_close(&c));
        assert_success(cpn_join(&t, NULL));
    }

    assert_success(cpn_server_close(&s));
}

static void encryption_initiation_succeeds()
{
    struct cpn_thread t;
    struct await_encryption_args args = {
        &remote, &remote_keys
    };

    cpn_spawn(&t, await_encryption, &args);
    assert_success(cpn_proto_initiate_encryption(&local,
                &local_keys, &remote_keys.pk));
    cpn_join(&t, NULL);

    assert(local.crypto == CPN_CHANNEL_CRYPTO_SYMMETRIC);
    assert_memory_equal(&local.key, &remote.key, sizeof(local.key));
    assert_memory_equal(local.local_nonce, remote.remote_nonce, sizeof(local.local_nonce));
    assert_memory_equal(local.remote_nonce, remote.local_nonce, sizeof(local.local_nonce));
}

static void encryption_initiation_fails_with_wrong_remote_key()
{
    struct cpn_thread t;
    struct await_encryption_args args = {
        &remote, &remote_keys
    };

    cpn_spawn(&t, await_encryption, &args);

    assert_failure(cpn_proto_initiate_encryption(&local,
                &local_keys, &local_keys.pk));

    shutdown(local.fd, SHUT_RDWR);
    shutdown(remote.fd, SHUT_RDWR);
    cpn_join(&t, NULL);
}

static void query_succeeds()
{
    struct cpn_thread t;
    struct await_query_args args = {
        { &remote, &remote_keys }, &service
    };
    struct cpn_query_results results;

    cpn_spawn(&t, await_query, &args);
    assert_success(cpn_proto_initiate_encryption(&local,
                &local_keys, &remote_keys.pk));
    assert_success(cpn_proto_send_query(&results, &local));
    cpn_join(&t, NULL);

    assert_string_equal(results.name, "Foo");
    assert_string_equal(results.type, "test");
    assert_string_equal(results.category, "Test");
    assert_string_equal(results.location, "Dunno");
    assert_string_equal(results.port, "1234");
    assert_string_equal(results.version, "0.0.1");
    assert_int_equal(results.nparams, 1);
    assert_string_equal(results.params[0].key, "test");

    cpn_query_results_free(&results);
}

static void whitelisted_query_succeeds()
{
    struct await_query_args args = {
        { &remote, &remote_keys }, &service
    };
    struct cpn_thread t;
    struct cpn_query_results results;

    cpn_spawn(&t, await_query, &args);
    assert_success(cpn_proto_initiate_encryption(&local,
                &local_keys, &remote_keys.pk));
    assert_success(cpn_proto_send_query(&results, &local));
    cpn_join(&t, NULL);

    cpn_query_results_free(&results);
}

static void request_constructs_session()
{
    struct cpn_parameter params[] = {
        { "port", "9999" }
    };
    struct await_request_args args = {
        { &remote, &remote_keys }, &service, &local_keys.pk, NULL, 0
    };
    struct cpn_cap invoker, requester;
    struct cpn_session added;
    struct cpn_thread t;

    cpn_spawn(&t, await_request, &args);
    assert_success(cpn_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_success(cpn_proto_send_request(&invoker, &requester, &local, &local_keys.pk, params, ARRAY_SIZE(params)));
    cpn_join(&t, NULL);

    assert_success(cpn_sessions_remove(&added, invoker.objectid));
    assert_int_equal(invoker.objectid, added.sessionid);

    cpn_session_free(&added);
}

static void request_without_params_succeeds()
{
    struct await_request_args args = {
        { &remote, &remote_keys }, &service, &local_keys.pk, NULL, 0
    };
    struct cpn_cap invoker, requester;
    struct cpn_session added;
    struct cpn_thread t;

    cpn_spawn(&t, await_request, &args);
    assert_success(cpn_proto_initiate_encryption(&local, &local_keys, &remote_keys.pk));
    assert_success(cpn_proto_send_request(&invoker, &requester, &local, &local_keys.pk, NULL, 0));
    cpn_join(&t, NULL);

    assert_success(cpn_sessions_remove(&added, invoker.objectid));
    assert_int_equal(invoker.objectid, added.sessionid);
    assert_int_equal(added.nparameters, 0);

    cpn_session_free(&added);
}

static void whitlisted_request_constructs_session()
{
    struct cpn_parameter params[] = {
        { "port", "9999" }
    };
    struct await_request_args args = {
        { &remote, &remote_keys }, &service, &local_keys.pk, &local_keys.pk, 1
    };
    struct cpn_session added;
    struct cpn_thread t;
    struct cpn_cap invoker, requester;

    cpn_spawn(&t, await_request, &args);
    assert_success(cpn_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_success(cpn_proto_send_request(&invoker, &requester, &local, &local_keys.pk, params, ARRAY_SIZE(params)));
    cpn_join(&t, NULL);

    assert_success(cpn_sessions_remove(&added, invoker.objectid));
    assert_int_equal(invoker.objectid, added.sessionid);

    cpn_session_free(&added);
}

static void service_connects()
{
    struct cpn_parameter params[] = {
        { "data", "parameter-data" }
    };
    struct handle_session_args args = {
        { &remote, &remote_keys }, &local_keys.pk, &service, &config
    };
    struct cpn_cap cap;
    struct cpn_thread t;
    uint32_t sessionid;
    uint8_t *received;

    cpn_spawn(&t, handle_session, &args);

    assert_success(cpn_sessions_add(&sessionid, params, ARRAY_SIZE(params)));
    assert_success(cpn_caps_add(sessionid));
    assert_success(cpn_caps_create_reference(&cap, sessionid, CPN_CAP_RIGHT_EXEC, &local_keys.pk));

    assert_success(cpn_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_success(cpn_proto_initiate_session(&local, &cap));
    assert_success(service.invoke(&local, 0, NULL) < 0);

    cpn_join(&t, NULL);

    received = cpn_test_service_get_data();
    assert_string_equal(params[0].value, received);
}

static void connect_refuses_without_session()
{
    struct handle_session_args args = {
        { &remote, &remote_keys }, &local_keys.pk, &service, &config
    };
    struct cpn_thread t;
    struct cpn_cap cap;

    cpn_spawn(&t, handle_session, &args);

    assert_success(cpn_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_failure(cpn_proto_initiate_session(&local, &cap));

    cpn_join(&t, NULL);
}

static void termination_kills_session()
{
    struct handle_termination_args args = {
        &remote, &local_keys.pk
    };
    struct cpn_thread t;
    struct cpn_cap cap;
    uint32_t sessionid;

    assert_success(cpn_sessions_add(&sessionid, NULL, 0));
    assert_success(cpn_caps_add(sessionid));
    assert_success(cpn_caps_create_reference(&cap, sessionid, CPN_CAP_RIGHT_TERM, &local_keys.pk));

    cpn_spawn(&t, handle_termination, &args);
    assert_success(cpn_proto_initiate_termination(&local, &cap));
    cpn_join(&t, NULL);

    assert_failure(cpn_sessions_find(NULL, sessionid));
}

static void terminating_nonexistent_does_nothing()
{
    struct handle_termination_args args = {
        &remote, &local_keys.pk
    };
    struct cpn_thread t;
    struct cpn_cap cap;

    cpn_spawn(&t, handle_termination, &args);
    assert_success(cpn_proto_initiate_termination(&local, &cap));
    cpn_join(&t, NULL);
}

int proto_test_run_suite(void)
{
    static const char *service_cfg =
        "[service]\n"
        "name=Foo\n"
        "type=test\n"
        "location=Dunno\n"
        "port=1234\n";
    struct cpn_service service;

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

    assert_success(cpn_test_init_service(&service));
    assert_success(cpn_service_register(&service));

    assert_success(cpn_sessions_init());

    assert_success(cpn_cfg_parse_string(&config, service_cfg, strlen(service_cfg)));
    assert_success(cpn_service_from_config(&service, "Foo", &config));

    assert_success(cpn_sign_key_pair_generate(&local_keys));
    assert_success(cpn_sign_key_pair_generate(&remote_keys));

    return execute_test_suite("proto", tests, setup, teardown);
}
