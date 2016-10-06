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

#include "capone/buf.h"

#include "test.h"

static struct cpn_buf buf;

static int setup()
{
    struct cpn_buf tmp = CPN_BUF_INIT;
    memcpy(&buf, &tmp, sizeof(struct cpn_buf));
    return 0;
}

static int teardown()
{
    cpn_buf_clear(&buf);
    return 0;
}

static void setting_buf_to_string_succeeds()
{
    assert_success(cpn_buf_set(&buf, "test"));
    assert_string_equal(buf.data, "test");
}

static void setting_buf_overwrites_content()
{
    assert_success(cpn_buf_set(&buf, "test"));
    assert_success(cpn_buf_set(&buf, "other"));
    assert_string_equal(buf.data, "other");
}

static void setting_buf_updates_length()
{
    assert_success(cpn_buf_set(&buf, "test"));
    assert_int_equal(buf.length, strlen("test"));
    assert_success(cpn_buf_set(&buf, "longerstring"));
    assert_int_equal(buf.length, strlen("longerstring"));
    assert_success(cpn_buf_set(&buf, "s"));
    assert_int_equal(buf.length, strlen("s"));
}

static void appending_empty_buf_succeeds()
{
    assert_success(cpn_buf_append(&buf, "test"));
    assert_string_equal(buf.data, "test");
}

static void appending_twice_concatenates()
{
    assert_success(cpn_buf_append(&buf, "test"));
    assert_success(cpn_buf_append(&buf, "test"));
    assert_string_equal(buf.data, "testtest");
}

static void appending_empty_does_nothing()
{
    assert_success(cpn_buf_append(&buf, "test"));
    assert_success(cpn_buf_append(&buf, ""));
    assert_string_equal(buf.data, "test");
}

static void appending_hex_succeeds()
{
    unsigned char bytes[] = { 0x01, 0x02, 0x03, 0x04 };
    assert_success(cpn_buf_append_hex(&buf, bytes, 4));
    assert_string_equal(buf.data, "01020304");
}

static void printf_succeeds_on_empty_buf()
{
    assert_success(cpn_buf_printf(&buf, "%s", "test"));
    assert_string_equal(buf.data, "test");
}

static void printf_succeeds_on_nonempty_buf()
{
    assert_success(cpn_buf_set(&buf, "test"));
    assert_success(cpn_buf_printf(&buf, "%s", "concatenated"));
    assert_string_equal(buf.data, "testconcatenated");
}

int buf_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(setting_buf_to_string_succeeds),
        test(setting_buf_overwrites_content),
        test(setting_buf_updates_length),

        test(appending_empty_buf_succeeds),
        test(appending_twice_concatenates),
        test(appending_empty_does_nothing),
        test(appending_hex_succeeds),

        test(printf_succeeds_on_empty_buf),
        test(printf_succeeds_on_nonempty_buf)
    };

    return execute_test_suite("buf", tests, NULL, NULL);
}
