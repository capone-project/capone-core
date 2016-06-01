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

#include "lib/common.h"
#include "lib/keys.h"
#include "lib/session.h"
#include "lib/service.h"

#include "test.h"

#define MAX_SESSIONS 1024

struct add_session_args {
    int sessionid;
};

static struct sd_sign_key_pair key;

static int setup()
{
    assert_success(sd_sign_key_pair_generate(&key));

    return 0;
}

static int teardown()
{
    assert_success(sd_sessions_clear());
    return 0;
}

static void add_sessions_adds_session()
{
    struct sd_session session;

    assert_success(sd_sessions_add(0, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_remove(&session, 0, &key.pk));

    assert_int_equal(session.sessionid, 0);
    assert_memory_equal(&session.issuer, &key.pk, sizeof(session.issuer));
    assert_memory_equal(&session.invoker, &key.pk, sizeof(session.invoker));
    assert_int_equal(session.nparameters, 0);
    assert_null(session.parameters);
}

static void add_session_with_params_succeeds()
{
    struct sd_parameter params[] = {
        { "data", "block" }
    };
    struct sd_session session;

    assert_success(sd_sessions_add(0, &key.pk, &key.pk, params, ARRAY_SIZE(params)));
    assert_success(sd_sessions_remove(&session, 0, &key.pk));

    assert_int_equal(session.nparameters, 1);
    assert_string_equal(session.parameters[0].key, params[0].key);
    assert_string_equal(session.parameters[0].value, params[0].value);

    sd_session_free(&session);
}

static void adding_session_twice_fails()
{
    assert_success(sd_sessions_add(0, &key.pk, &key.pk, NULL, 0));
    assert_failure(sd_sessions_add(0, &key.pk, &key.pk, NULL, 0));
}

static void adding_too_many_sessions_fails()
{
    size_t i;

    for (i = 0; i < MAX_SESSIONS; i++) {
        assert_success(sd_sessions_add(i, &key.pk, &key.pk, NULL, 0));
    }

    assert_failure(sd_sessions_add(MAX_SESSIONS, &key.pk, &key.pk, NULL, 0));
}

static void *add_session(void *payload)
{
    struct add_session_args *args = (struct add_session_args *) payload;

    assert_success(sd_sessions_add(args->sessionid, &key.pk, &key.pk, NULL, 0));

    return NULL;
}

static void adding_session_from_multiple_threads_succeeds()
{
    struct sd_thread threads[MAX_SESSIONS];
    struct add_session_args args[MAX_SESSIONS];
    struct sd_session session;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        args[i].sessionid = i;
        assert_success(sd_spawn(&threads[i], add_session, &args[i]));
    }

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        assert_success(sd_join(&threads[i], NULL));
    }

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        assert_success(sd_sessions_remove(&session, i, &key.pk));
        assert_int_equal(session.sessionid, i);
    }
}

static void adding_session_with_different_invoker_succeeds()
{
    struct sd_session out;
    struct sd_sign_key_public other_pk;

    assert_success(sd_sessions_add(0, &key.pk, &other_pk, NULL, 0));
    assert_success(sd_sessions_remove(&out, 0, &other_pk));

    assert_int_equal(out.sessionid, 0);
    assert_memory_equal(&out.issuer, &key.pk, sizeof(out.issuer));
    assert_memory_equal(&out.invoker, &other_pk, sizeof(out.invoker));
}

static void removing_session_twice_fails()
{
    struct sd_session session;

    assert_success(sd_sessions_add(0, &key.pk, &key.pk, NULL, 0));

    assert_success(sd_sessions_remove(&session, 0, &key.pk));
    assert_failure(sd_sessions_remove(&session, 0, &key.pk));
}

static void remove_session_fails_without_sessions()
{
    struct sd_session session;

    assert_failure(sd_sessions_remove(&session, 0, &key.pk));
}

static void remove_session_fails_for_empty_session()
{
    struct sd_session session;
    struct sd_sign_key_public key;

    memset(&key, 0, sizeof(key));

    assert_failure(sd_sessions_remove(&session, 0, &key));
}

static void remove_session_frees_space()
{
    size_t i;
    struct sd_session session;

    for (i = 0; i < MAX_SESSIONS; i++) {
        assert_success(sd_sessions_add(i, &key.pk, &key.pk, NULL, 0));
    }

    assert_failure(sd_sessions_add(MAX_SESSIONS + 1, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_remove(&session, 0, &key.pk));
    assert_success(sd_sessions_add(MAX_SESSIONS + 1, &key.pk, &key.pk, NULL, 0));
}

static void finding_invalid_session_fails()
{
    struct sd_session out;

    assert_failure(sd_sessions_find(&out, 0, &key.pk));
}

static void finding_session_with_invalid_id_fails()
{
    struct sd_session out;

    assert_success(sd_sessions_add(0, &key.pk, &key.pk, NULL, 0));
    assert_failure(sd_sessions_find(&out, 1, &key.pk));
}

static void finding_session_with_invalid_key_fails()
{
    struct sd_session out;
    struct sd_sign_key_public other_key;

    assert_success(sd_sessions_add(0, &key.pk, &key.pk, NULL, 0));
    assert_failure(sd_sessions_find(&out, 0, &other_key));
}

static void finding_existing_session_succeeds()
{
    struct sd_session out;

    assert_success(sd_sessions_add(0, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_find(&out, 0, &key.pk));

    assert_int_equal(out.sessionid, 0);
    assert_memory_equal(&out.issuer, &key.pk, sizeof(out.issuer));
    assert_memory_equal(&out.invoker, &key.pk, sizeof(out.invoker));
}

static void finding_session_without_out_param_succeeds()
{
    assert_success(sd_sessions_add(0, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_find(NULL, 0, &key.pk));
}

static void finding_intermediate_session_returns_correct_index()
{
    assert_success(sd_sessions_add(5, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(8, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(3, &key.pk, &key.pk, NULL, 0));

    assert_int_equal(sd_sessions_find(NULL, 8, &key.pk), 1);
}

static void finding_session_with_multiple_sessions_succeeds()
{
    struct sd_sign_key_public other_key;
    struct sd_session out;

    assert_success(sd_sessions_add(0, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(1, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(2, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(3, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(0, &other_key, &other_key, NULL, 0));
    assert_success(sd_sessions_add(1, &other_key, &other_key, NULL, 0));
    assert_success(sd_sessions_add(2, &other_key, &other_key, NULL, 0));
    assert_success(sd_sessions_add(3, &other_key, &other_key, NULL, 0));

    assert_int_equal(sd_sessions_find(&out, 3, &key.pk), 3);

    assert_int_equal(out.sessionid, 3);
    assert_memory_equal(&out.issuer, &key.pk, sizeof(out.issuer));
    assert_memory_equal(&out.invoker, &key.pk, sizeof(out.invoker));
}

static void finding_session_by_invoker_succeeds()
{
    struct sd_sign_key_public other_key;
    struct sd_session out;

    assert_success(sd_sessions_add(0, &key.pk, &other_key, NULL, 0));
    assert_success(sd_sessions_remove(&out, 0, &other_key));

    assert_int_equal(out.sessionid, 0);
    assert_memory_equal(&out.issuer, &key.pk, sizeof(out.issuer));
    assert_memory_equal(&out.invoker, &other_key, sizeof(out.invoker));
}

static void free_session_succeeds_without_params()
{
    struct sd_session session = { 0, { { 0 } }, { { 0 } }, NULL, 0 };

    sd_session_free(&session);
}

static void free_session_succeeds_with_params()
{
    struct sd_session session;

    session.nparameters = 1;
    session.parameters = malloc(sizeof(struct sd_parameter));
    session.parameters[0].key = strdup("data");
    session.parameters[0].value = strdup("block");

    sd_session_free(&session);
}

static void free_session_succeeds_with_key_only_parameter()
{
    struct sd_session session;

    session.nparameters = 1;
    session.parameters = malloc(sizeof(struct sd_parameter));
    session.parameters[0].key = strdup("data");
    session.parameters[0].value = NULL;

    sd_session_free(&session);
}

int session_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(add_sessions_adds_session),
        test(add_session_with_params_succeeds),
        test(adding_session_twice_fails),
        test(adding_too_many_sessions_fails),
        test(adding_session_from_multiple_threads_succeeds),
        test(adding_session_with_different_invoker_succeeds),

        test(removing_session_twice_fails),
        test(remove_session_fails_without_sessions),
        test(remove_session_fails_for_empty_session),
        test(remove_session_frees_space),

        test(finding_invalid_session_fails),
        test(finding_session_with_invalid_id_fails),
        test(finding_session_with_invalid_key_fails),
        test(finding_existing_session_succeeds),
        test(finding_session_without_out_param_succeeds),
        test(finding_intermediate_session_returns_correct_index),
        test(finding_session_with_multiple_sessions_succeeds),
        test(finding_session_by_invoker_succeeds),

        test(free_session_succeeds_without_params),
        test(free_session_succeeds_with_params),
        test(free_session_succeeds_with_key_only_parameter)
    };

    assert_success(sd_sessions_init());

    return execute_test_suite("proto", tests, setup, teardown);
}
