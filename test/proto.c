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
#include "lib/service.h"
#include "lib/session.h"

#include "lib/service/test.h"

#include "test.h"

extern void stub_sockets(struct sd_channel *local, struct sd_channel *remote);

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
    struct cfg *cfg;
};

struct send_query_args {
    struct sd_channel *c;
    struct sd_sign_key_pair *k;
    struct sd_sign_key_public *r;
};

struct send_request_args {
    struct sd_channel *channel;
    struct sd_sign_key_pair *channel_key;
    struct sd_sign_key_public *remote_key;
    struct sd_service_parameter *params;
    size_t nparams;
};

static struct cfg config;
static struct sd_service service;
static struct sd_channel local, remote;
static struct sd_sign_key_pair local_keys, remote_keys;
static struct sd_sign_key_public dummy_whitelist;

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
    return 0;
}

static void *await_encryption(void *payload)
{
    struct await_encryption_args *args = (struct await_encryption_args *) payload;
    struct sd_sign_key_public remote_key;

    assert_success(sd_proto_await_encryption(args->c, args->k, &remote_key));
    assert_memory_equal(&remote_key, &local_keys.pk, sizeof(remote_key));
    assert(args->c->crypto == SD_CHANNEL_CRYPTO_SYMMETRIC);

    return NULL;
}

static void *await_query(void *payload)
{
    struct await_query_args *args = (struct await_query_args *) payload;

    await_encryption(&args->enc_args);

    assert_success(sd_proto_answer_query(args->enc_args.c, args->s,
                args->r, args->whitelist, args->nwhitelist));

    return NULL;
}

static void *await_request(void *payload)
{
    struct await_request_args *args = (struct await_request_args *) payload;

    await_encryption(&args->enc_args);

    assert_success(sd_proto_answer_request(args->enc_args.c,
                args->r, args->whitelist, args->nwhitelist));

    return NULL;
}

static void *handle_session(void *payload)
{
    struct handle_session_args *args = (struct handle_session_args *) payload;

    await_encryption(&args->enc_args);

    assert_success(sd_proto_handle_session(args->enc_args.c,
                args->remote_key, args->service, args->cfg));

    return NULL;
}

static void *send_query(void *payload)
{
    struct send_query_args *args = (struct send_query_args *) payload;
    struct sd_query_results results;

    assert_success(sd_proto_initiate_encryption(args->c,
                args->k, args->r));
    assert_success(sd_proto_send_query(&results, args->c));

    sd_query_results_free(&results);

    return NULL;
}

static void *send_request(void *payload)
{
    struct send_request_args *args = (struct send_request_args *) payload;
    struct sd_session session;

    assert_success(sd_proto_initiate_encryption(args->channel,
                args->channel_key, args->remote_key));
    assert_success(sd_proto_send_request(&session, args->channel, args->remote_key,
                args->params, args->nparams));

    return NULL;
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
    sd_channel_close(&local);
    sd_kill(&t);
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

static void blacklisted_query_fails()
{
    /* Add remote key as whitelisted key only */
    struct send_query_args args = {
        &local, &local_keys, &remote_keys.pk
    };
    struct sd_thread t;
    struct sd_sign_key_public received_sign_key;

    sd_spawn(&t, send_query, &args);
    assert_success(sd_proto_await_encryption(&remote,
                &remote_keys, &received_sign_key));
    assert_failure(sd_proto_answer_query(&remote,
                &service, &local_keys.pk, &dummy_whitelist, 1));
    sd_kill(&t);
}

static void request_constructs_session()
{
    static const char *port[] = { "9999" };
    struct sd_service_parameter params[] = {
        { "port", 1, port }
    };
    struct await_request_args args = {
        { &remote, &remote_keys }, &service, &local_keys.pk, NULL, 0
    };
    struct sd_session session, added;
    struct sd_thread t;

    sd_spawn(&t, await_request, &args);
    assert_success(sd_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_success(sd_proto_send_request(&session, &local, &local_keys.pk,
                params, ARRAY_SIZE(params)));
    sd_join(&t, NULL);

    assert_success(sd_sessions_remove(&added, session.sessionid, &session.identity));
    assert_int_equal(session.sessionid, added.sessionid);
    assert_memory_equal(&session.identity, &added.identity, sizeof(session.identity));
}

static void whitlisted_request_constructs_session()
{
    static const char *port[] = { "9999" };
    struct sd_service_parameter params[] = {
        { "port", 1, port }
    };
    struct await_request_args args = {
        { &remote, &remote_keys }, &service, &local_keys.pk, &local_keys.pk, 1
    };
    struct sd_session session, added;
    struct sd_thread t;

    sd_spawn(&t, await_request, &args);
    assert_success(sd_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_success(sd_proto_send_request(&session, &local, &local_keys.pk,
                params, ARRAY_SIZE(params)));
    sd_join(&t, NULL);

    assert_success(sd_sessions_remove(&added, session.sessionid, &session.identity));
    assert_int_equal(session.sessionid, added.sessionid);
    assert_memory_equal(&session.identity, &added.identity, sizeof(session.identity));
}

static void blacklisted_request_fails()
{
    static const char *port[] = { "9999" };
    static struct sd_service_parameter params[] = {
        { "port", 1, port }
    };
    struct send_request_args args = {
        &local, &local_keys , &remote_keys.pk, params, ARRAY_SIZE(params)
    };
    struct sd_sign_key_public received_sign_key;
    struct sd_thread t;

    sd_spawn(&t, send_request, &args);
    assert_success(sd_proto_await_encryption(&remote, &remote_keys,
                &received_sign_key));
    assert_failure(sd_proto_answer_request(&remote, &received_sign_key,
                &dummy_whitelist, 1));
    sd_kill(&t);
}

static void service_connects()
{
    struct sd_service_parameter *params;
    struct handle_session_args args = {
        { &remote, &remote_keys }, &local_keys.pk, &service, &config
    };
    struct sd_thread t;
    uint8_t *received;
    char *data = "parameter-data";

    params = malloc(sizeof(struct sd_service_parameter));
    params[0].key = "data";
    params[0].values = malloc(sizeof(char *));
    params[0].values[0] = strdup(data);

    sd_spawn(&t, handle_session, &args);

    assert_success(sd_sessions_add(1, &local_keys.pk,
                params, ARRAY_SIZE(params)));
    assert_success(sd_proto_initiate_encryption(&local, &local_keys,
                &remote_keys.pk));
    assert_success(sd_proto_initiate_session(&local, 1));
    assert_success(service.invoke(&local, 0, NULL) < 0);

    sd_join(&t, NULL);

    received = sd_test_service_get_data();
    assert_string_equal(data, received);
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
        test(encryption_initiation_succeeds),
        test(encryption_initiation_fails_with_wrong_remote_key),
        test(query_succeeds),
        test(whitelisted_query_succeeds),
        test(blacklisted_query_fails),
        test(request_constructs_session),
        test(whitlisted_request_constructs_session),
        test(blacklisted_request_fails),
        test(service_connects)
    };

    assert_success(sd_sessions_init());

    assert_success(cfg_parse_string(&config, service_cfg, strlen(service_cfg)));
    assert_success(sd_service_from_config(&service, "Foo", &config));

    assert_success(sd_sign_key_pair_generate(&local_keys));
    assert_success(sd_sign_key_pair_generate(&remote_keys));

    return execute_test_suite("proto", tests, setup, teardown);
}
