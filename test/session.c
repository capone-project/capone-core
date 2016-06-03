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

static struct sd_sign_key_pair key;
static uint32_t id;

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

    assert_success(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_remove(&session, id, &key.pk));

    assert_int_equal(session.sessionid, id);
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

    assert_success(sd_sessions_add(&id, &key.pk, &key.pk, params, ARRAY_SIZE(params)));
    assert_success(sd_sessions_remove(&session, id, &key.pk));

    assert_int_equal(session.nparameters, 1);
    assert_string_equal(session.parameters[0].key, params[0].key);
    assert_string_equal(session.parameters[0].value, params[0].value);

    sd_session_free(&session);
}

static void adding_too_many_sessions_fails()
{
    size_t i;

    for (i = 0; i < MAX_SESSIONS; i++) {
        assert_success(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));
    }

    assert_failure(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));
}

static void *add_session(void *ptr)
{
    assert_success(sd_sessions_add((uint32_t *) ptr, &key.pk, &key.pk, NULL, 0));

    return (void *)(long) id;
}

static void adding_session_from_multiple_threads_succeeds()
{
    struct sd_thread threads[MAX_SESSIONS];
    uint32_t ids[ARRAY_SIZE(threads)];
    struct sd_session session;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        assert_success(sd_spawn(&threads[i], add_session, &ids[i]));
    }

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        assert_success(sd_join(&threads[i], NULL));
    }

    for (i = 0; i < ARRAY_SIZE(threads); i++) {
        assert_success(sd_sessions_remove(&session, ids[i], &key.pk));
        assert_int_equal(session.sessionid, ids[i]);
    }
}

static void adding_session_with_different_invoker_succeeds()
{
    struct sd_session out;
    struct sd_sign_key_public other_pk;

    assert_success(sd_sessions_add(&id, &key.pk, &other_pk, NULL, 0));
    assert_success(sd_sessions_remove(&out, id, &other_pk));

    assert_int_equal(out.sessionid, id);
    assert_memory_equal(&out.issuer, &key.pk, sizeof(out.issuer));
    assert_memory_equal(&out.invoker, &other_pk, sizeof(out.invoker));
}

static void removing_session_twice_fails()
{
    struct sd_session session;

    assert_success(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));

    assert_success(sd_sessions_remove(&session, id, &key.pk));
    assert_failure(sd_sessions_remove(&session, id, &key.pk));
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
        assert_success(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));
    }

    assert_failure(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_remove(&session, id, &key.pk));
    assert_success(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));
}

static void finding_invalid_session_fails()
{
    struct sd_session out;

    assert_failure(sd_sessions_find(&out, 0, &key.pk));
}

static void finding_session_with_invalid_id_fails()
{
    struct sd_session out;

    assert_success(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));
    assert_failure(sd_sessions_find(&out, id + 1, &key.pk));
}

static void finding_session_with_invalid_key_fails()
{
    struct sd_session out;
    struct sd_sign_key_public other_key;

    assert_success(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));
    assert_failure(sd_sessions_find(&out, id, &other_key));
}

static void finding_existing_session_succeeds()
{
    struct sd_session out;

    assert_success(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_find(&out, id, &key.pk));

    assert_int_equal(out.sessionid, id);
    assert_memory_equal(&out.issuer, &key.pk, sizeof(out.issuer));
    assert_memory_equal(&out.invoker, &key.pk, sizeof(out.invoker));
}

static void finding_session_without_out_param_succeeds()
{
    assert_success(sd_sessions_add(&id, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_find(NULL, id, &key.pk));
}

static void finding_intermediate_session_returns_correct_index()
{
    struct sd_session out;
    uint32_t id1, id2, id3;

    assert_success(sd_sessions_add(&id1, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(&id2, &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(&id3, &key.pk, &key.pk, NULL, 0));

    assert_success(sd_sessions_find(&out, id2, &key.pk));
    assert_int_equal(out.sessionid, id2);
}

static void finding_session_with_multiple_sessions_succeeds()
{
    struct sd_sign_key_public other_key;
    struct sd_session out;
    uint32_t ids[8];
    uint32_t i;

    assert_success(sd_sessions_add(&ids[0], &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(&ids[1], &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(&ids[2], &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(&ids[3], &key.pk, &key.pk, NULL, 0));
    assert_success(sd_sessions_add(&ids[4], &other_key, &other_key, NULL, 0));
    assert_success(sd_sessions_add(&ids[5], &other_key, &other_key, NULL, 0));
    assert_success(sd_sessions_add(&ids[6], &other_key, &other_key, NULL, 0));
    assert_success(sd_sessions_add(&ids[7], &other_key, &other_key, NULL, 0));

    for (i = 0; i < 4; i++) {
        assert_success(sd_sessions_find(&out, ids[i], &key.pk));
        assert_int_equal(out.sessionid, ids[i]);
        assert_memory_equal(&out.issuer, &key.pk, sizeof(out.issuer));
        assert_memory_equal(&out.invoker, &key.pk, sizeof(out.invoker));
    }

    for (i = 4; i < 8; i++) {
        assert_success(sd_sessions_find(&out, ids[i], &other_key));
        assert_int_equal(out.sessionid, ids[i]);
        assert_memory_equal(&out.issuer, &other_key, sizeof(out.issuer));
        assert_memory_equal(&out.invoker, &other_key, sizeof(out.invoker));
    }
}

static void finding_session_by_invoker_succeeds()
{
    struct sd_sign_key_public other_key;
    struct sd_session out;

    assert_success(sd_sessions_add(&id, &key.pk, &other_key, NULL, 0));
    assert_success(sd_sessions_remove(&out, id, &other_key));

    assert_int_equal(out.sessionid, id);
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
