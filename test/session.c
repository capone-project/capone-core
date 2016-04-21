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

    assert_success(sd_sessions_add(0, &key.pk, NULL, 0));

    assert_success(sd_sessions_remove(&session, 0, &key.pk));
    assert_int_equal(session.sessionid, 0);
    assert_memory_equal(&session.identity, &key.pk, sizeof(session.identity));
    assert_int_equal(session.nparameters, 0);
    assert_null(session.parameters);
}

static void add_session_with_params_succeeds()
{
    struct sd_service_parameter params[] = {
        { "data", "block" }
    };
    struct sd_session session;

    assert_success(sd_sessions_add(0, &key.pk, params, ARRAY_SIZE(params)));
    assert_success(sd_sessions_remove(&session, 0, &key.pk));

    assert_int_equal(session.nparameters, 1);
    assert_string_equal(session.parameters[0].key, params[0].key);
    assert_string_equal(session.parameters[0].value, params[0].value);

    sd_session_free(&session);
}

static void adding_session_twice_fails()
{
    assert_success(sd_sessions_add(0, &key.pk, NULL, 0));
    assert_failure(sd_sessions_add(0, &key.pk, NULL, 0));
}

static void adding_too_many_sessions_fails()
{
    size_t i;

    for (i = 0; i < MAX_SESSIONS; i++) {
        assert_success(sd_sessions_add(i, &key.pk, NULL, 0));
    }

    assert_failure(sd_sessions_add(MAX_SESSIONS, &key.pk, NULL, 0));
}

static void *add_session(void *payload)
{
    struct add_session_args *args = (struct add_session_args *) payload;

    assert_success(sd_sessions_add(args->sessionid, &key.pk, NULL, 0));

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

static void removing_session_twice_fails()
{
    struct sd_session session;

    assert_success(sd_sessions_add(0, &key.pk, NULL, 0));

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
        assert_success(sd_sessions_add(i, &key.pk, NULL, 0));
    }

    assert_failure(sd_sessions_add(MAX_SESSIONS + 1, &key.pk, NULL, 0));
    assert_success(sd_sessions_remove(&session, 0, &key.pk));
    assert_success(sd_sessions_add(MAX_SESSIONS + 1, &key.pk, NULL, 0));
}

static void free_session_succeeds_without_params()
{
    struct sd_session session = { 0, { { 0 } }, NULL, 0 };

    sd_session_free(&session);
}

static void free_session_succeeds_with_params()
{
    struct sd_session session;

    session.nparameters = 1;
    session.parameters = malloc(sizeof(struct sd_service_parameter));
    session.parameters[0].key = strdup("data");
    session.parameters[0].value = strdup("block");

    sd_session_free(&session);
}

static void free_session_succeeds_with_key_only_parameter()
{
    struct sd_session session;

    session.nparameters = 1;
    session.parameters = malloc(sizeof(struct sd_service_parameter));
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
        test(removing_session_twice_fails),
        test(remove_session_fails_without_sessions),
        test(remove_session_fails_for_empty_session),
        test(remove_session_frees_space),
        test(free_session_succeeds_without_params),
        test(free_session_succeeds_with_params),
        test(free_session_succeeds_with_key_only_parameter)
    };

    assert_success(sd_sessions_init());

    return execute_test_suite("proto", tests, setup, teardown);
}
