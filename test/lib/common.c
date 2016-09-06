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
#include <time.h>

#include "capone/common.h"

#include "test.h"

static int data;

static int setup()
{
    data = 0;
    return 0;
}

static int teardown()
{
    return 0;
}

static void *spawn_fn(void *payload)
{
    if (payload) {
        data = *(int *) payload;
    } else {
        data = 1;
    }

    return &data;
}

static void *blocking_fn()
{
    struct timespec t = { 1, 0 };

    while (1) {
        nanosleep(&t, NULL);
    }
    return NULL;
}

static void spawn_with_null_thread_succeeds()
{
    struct timespec t;
    int i;

    t.tv_sec = 0;
    t.tv_nsec = 100000;

    assert_success(cpn_spawn(NULL, spawn_fn, NULL));

    for (i = 0; i < 20; i++) {
        if (data == 1)
            return;
        assert_success(nanosleep(&t, NULL));
    }

    fail();
}

static void kill_succeeds_for_running_thread()
{
    struct cpn_thread t;

    assert_success(cpn_spawn(&t, blocking_fn, NULL));
    assert_success(cpn_kill(&t));
}

static void join_gets_result()
{
    struct cpn_thread t;
    int *ptr;

    assert_success(cpn_spawn(&t, spawn_fn, NULL));
    assert_success(cpn_join(&t, (void **) &ptr));
    assert_ptr_equal(ptr, &data);
}

static void join_without_retval_succeeds()
{
    struct cpn_thread t;

    assert_success(cpn_spawn(&t, spawn_fn, NULL));
    assert_success(cpn_join(&t, NULL));
}

static void spawn_hands_over_arg()
{
    struct cpn_thread t;
    int i = 2;

    assert_success(cpn_spawn(&t, spawn_fn, &i));
    assert_success(cpn_join(&t, NULL));
    assert_int_equal(i, data);
}

static void parsing_uint_succeeds()
{
    uint32_t i;
    char str[] = "123456";

    assert_success(parse_uint32t(&i, str));
    assert_int_equal(i, 123456);
}

static void parsing_negative_number_fails()
{
    uint32_t i;
    char str[] = "-123456";

    assert_failure(parse_uint32t(&i, str));
}

static void parsing_alphanum_fails()
{
    uint32_t i;
    char str[] = "abcd";

    assert_failure(parse_uint32t(&i, str));
}

static void parsing_string_with_trailing_number_fails()
{
    uint32_t i;
    char str[] = "abc123";

    assert_failure(parse_uint32t(&i, str));
}

static void parsing_string_with_leading_number_fails()
{
    uint32_t i;
    char str[] = "123abc";

    assert_failure(parse_uint32t(&i, str));
}

static void parsing_too_big_number_fails()
{
    uint32_t i;
    char str[] = "4294967296";

    assert_failure(parse_uint32t(&i, str));
}

static void parsing_uint64t_plus_1_fails()
{
    uint32_t i;
    char str[] = "18446744073709551618";

    assert_failure(parse_uint32t(&i, str));
}

static void parsing_hex_succeeds()
{
    uint8_t out[1];
    char str[] = "aa";
    assert_success(parse_hex(out, sizeof(out), str, strlen(str)));
}

static void parsing_longer_hex_succeeds()
{
    uint8_t out[8];
    char str[] = "aa13489570134572";
    assert_success(parse_hex(out, sizeof(out), str, strlen(str)));
}

static void parsing_hex_with_too_short_out_fails()
{
    uint8_t out[3];
    char str[] = "aa13489570134572";
    assert_failure(parse_hex(out, sizeof(out), str, strlen(str)));
}

static void parsing_hex_with_too_long_out_fails()
{
    uint8_t out[20];
    char str[] = "aa13489570134572";
    assert_failure(parse_hex(out, sizeof(out), str, strlen(str)));
}

static void parsing_hex_with_invalid_characters_fails()
{
    uint8_t out[1];
    char str[] = "zz";
    assert_failure(parse_hex(out, sizeof(out), str, strlen(str)));
}

static void parsing_hex_without_zero_termination_succeeds()
{
    uint8_t out[1];
    char str[2] = "ab";
    assert_success(parse_hex(out, sizeof(out), str, 2));
}

static void parsing_hex_with_shorter_strlen_succeeds()
{
    uint8_t out[1];
    char str[] = "abcd";
    assert_success(parse_hex(out, sizeof(out), str, 2));
}

int common_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(spawn_with_null_thread_succeeds),
        test(kill_succeeds_for_running_thread),
        test(join_gets_result),
        test(join_without_retval_succeeds),
        test(spawn_hands_over_arg),

        test(parsing_uint_succeeds),
        test(parsing_negative_number_fails),
        test(parsing_alphanum_fails),
        test(parsing_string_with_trailing_number_fails),
        test(parsing_string_with_leading_number_fails),
        test(parsing_too_big_number_fails),
        test(parsing_uint64t_plus_1_fails),

        test(parsing_hex_succeeds),
        test(parsing_longer_hex_succeeds),
        test(parsing_hex_with_too_short_out_fails),
        test(parsing_hex_with_too_long_out_fails),
        test(parsing_hex_with_invalid_characters_fails),
        test(parsing_hex_without_zero_termination_succeeds),
        test(parsing_hex_with_shorter_strlen_succeeds)
    };

    return execute_test_suite("common", tests, setup, teardown);
}
