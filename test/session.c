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

#include "capone/common.h"
#include "capone/keys.h"
#include "capone/session.h"
#include "capone/service.h"

#include "test.h"

static struct cpn_sign_key_public pk;
static const struct cpn_session *session;

static int setup()
{
    return 0;
}

static int teardown()
{
    session = NULL;
    assert_success(cpn_sessions_clear());
    return 0;
}

static void add_sessions_adds_session()
{
    struct cpn_session *removed;

    assert_success(cpn_sessions_add(&session, 0, NULL, &pk));
    assert_success(cpn_sessions_remove(&removed, session->cap.objectid));

    assert_int_equal(removed->cap.objectid, session->cap.objectid);
    assert_int_equal(removed->argc, 0);
    assert_null(removed->argv);
    assert_memory_equal(&removed->creator, &pk, sizeof(struct cpn_sign_key_public));

    cpn_session_free(removed);
}

static void add_session_with_params_succeeds()
{
    struct cpn_session *removed;
    const char *params[] = {
        "data", "block"
    };

    assert_success(cpn_sessions_add(&session, ARRAY_SIZE(params), params, &pk));
    assert_success(cpn_sessions_remove(&removed, session->cap.objectid));

    assert_int_equal(removed->argc, 2);
    assert_string_equal(removed->argv[0], params[0]);
    assert_string_equal(removed->argv[1], params[1]);

    cpn_session_free(removed);
}

static void *add_session(void *ptr)
{
    assert_success(cpn_sessions_add((const struct cpn_session **) ptr, 0, NULL, &pk));

    return NULL;
}

static void adding_session_from_multiple_threads_succeeds()
{
    const struct cpn_session *sessions[100];
    struct cpn_session *removed;
    struct cpn_thread threads[ARRAY_SIZE(sessions)];
    size_t i;

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        assert_success(cpn_spawn(&threads[i], add_session, &sessions[i]));
    }

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        assert_success(cpn_join(&threads[i], NULL));
    }

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        assert_success(cpn_sessions_remove(&removed, sessions[i]->cap.objectid));
        assert_int_equal(removed->cap.objectid, sessions[i]->cap.objectid);
        cpn_session_free(removed);
    }
}

static void adding_session_with_different_invoker_succeeds()
{
    struct cpn_session *removed;

    assert_success(cpn_sessions_add(&session, 0, NULL, &pk));
    assert_success(cpn_sessions_remove(&removed, session->cap.objectid));

    assert_int_equal(removed->cap.objectid, session->cap.objectid);
    cpn_session_free(removed);
}

static void removing_session_twice_fails()
{
    struct cpn_session *removed;
    uint32_t objectid;

    assert_success(cpn_sessions_add(&session, 0, NULL, &pk));
    objectid = session->cap.objectid;

    assert_success(cpn_sessions_remove(&removed, session->cap.objectid));
    cpn_session_free(removed);
    assert_failure(cpn_sessions_remove(&removed, objectid));
}

static void remove_session_fails_without_sessions()
{
    struct cpn_session *session;
    assert_failure(cpn_sessions_remove(&session, 0));
}

static void remove_session_fails_for_empty_session()
{
    struct cpn_sign_key_public key;
    struct cpn_session *session;

    memset(&key, 0, sizeof(key));

    assert_failure(cpn_sessions_remove(&session, 0));
}

static void finding_invalid_session_fails()
{
    assert_failure(cpn_sessions_find(&session, 0));
}

static void finding_session_with_invalid_id_fails()
{
    assert_success(cpn_sessions_add(&session, 0, NULL, &pk));
    assert_failure(cpn_sessions_find(&session, session->cap.objectid + 1));
}

static void finding_existing_session_succeeds()
{
    const struct cpn_session *found;

    assert_success(cpn_sessions_add(&session, 0, NULL, &pk));
    assert_success(cpn_sessions_find(&found, session->cap.objectid));

    assert_int_equal(found->cap.objectid, session->cap.objectid);
}

static void finding_session_without_out_param_succeeds()
{
    assert_success(cpn_sessions_add(&session, 0, NULL, &pk));
    assert_success(cpn_sessions_find(NULL, session->cap.objectid));
}

static void finding_intermediate_session_returns_correct_index()
{
    const struct cpn_session *sessions[3];

    assert_success(cpn_sessions_add(&sessions[0], 0, NULL, &pk));
    assert_success(cpn_sessions_add(&sessions[1], 0, NULL, &pk));
    assert_success(cpn_sessions_add(&sessions[2], 0, NULL, &pk));

    assert_success(cpn_sessions_find(&session, sessions[2]->cap.objectid));
    assert_int_equal(session, sessions[2]);
}

static void finding_session_with_multiple_sessions_succeeds()
{
    const struct cpn_session *sessions[8];
    uint32_t i;

    for (i = 0; i < ARRAY_SIZE(sessions); i++)
        assert_success(cpn_sessions_add(&sessions[i], 0, NULL, &pk));

    for (i = 0; i < ARRAY_SIZE(sessions); i++) {
        assert_success(cpn_sessions_find(&session, sessions[i]->cap.objectid));
        assert_int_equal(session->cap.objectid, sessions[i]->cap.objectid);
    }
}

static void free_session_succeeds_without_params()
{
    struct cpn_session *session = calloc(1, sizeof(struct cpn_session));
    cpn_session_free(session);
}

static void free_session_succeeds_with_params()
{
    struct cpn_session *session = calloc(1, sizeof(struct cpn_session));
    session->argc = 2;
    session->argv = malloc(sizeof(char *) * 2);
    session->argv[0] = strdup("data");
    session->argv[1] = strdup("block");

    cpn_session_free(session);
}

int session_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(add_sessions_adds_session),
        test(add_session_with_params_succeeds),
        test(adding_session_from_multiple_threads_succeeds),
        test(adding_session_with_different_invoker_succeeds),

        test(removing_session_twice_fails),
        test(remove_session_fails_without_sessions),
        test(remove_session_fails_for_empty_session),

        test(finding_invalid_session_fails),
        test(finding_session_with_invalid_id_fails),
        test(finding_existing_session_succeeds),
        test(finding_session_without_out_param_succeeds),
        test(finding_intermediate_session_returns_correct_index),
        test(finding_session_with_multiple_sessions_succeeds),

        test(free_session_succeeds_without_params),
        test(free_session_succeeds_with_params),
    };

    return execute_test_suite("proto", tests, setup, teardown);
}
