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

#include "capone/protobuf.h"

#include "test.h"
#include "test/lib/test.pb-c.h"

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

static void empty_protobuf_to_string_succeeds()
{
    TestParams params = TEST_PARAMS__INIT;
    assert_success(cpn_protobuf_to_string(&buf, 0, &params.base));
    assert_string_equal(buf.data, "msg: \n");
}

static void protobuf_with_fields_to_string_set_succeeds()
{
    TestParams params = TEST_PARAMS__INIT;
    params.msg = "Test";
    assert_success(cpn_protobuf_to_string(&buf, 0, &params.base));
    assert_string_equal(buf.data, "msg: Test\n");
}

static void indented_protobuf_to_string_succeeds()
{
    TestParams params = TEST_PARAMS__INIT;
    assert_success(cpn_protobuf_to_string(&buf, 2, &params.base));
    assert_string_equal(buf.data, "  msg: \n");
}

static void nested_protobuf_to_string_succeeds()
{
    TestNested nested = TEST_NESTED__INIT;
    TestParams params = TEST_PARAMS__INIT;
    TestMultiple mult = TEST_MULTIPLE__INIT;
    TestMessage msg = TEST_MESSAGE__INIT;

    params.msg = "uiae";
    mult.s = "values";
    mult.i = 1;
    msg.value = "test";

    nested.params = &params;
    nested.mult = &mult;
    nested.msg = &msg;

    assert_success(cpn_protobuf_to_string(&buf, 0, &nested.base));
    assert_string_equal(buf.data,
            "params {\n"
            "  msg: uiae\n"
            "}\n"
            "mult {\n"
            "  s: values\n"
            "  i: 1\n"
            "}\n"
            "msg {\n"
            "  value: test\n"
            "}\n");
}

static void types_to_string_succeeds()
{
    TestTypes types = TEST_TYPES__INIT;
    uint8_t bytes[] = { 0x01, 0x02, 0x03, 0x04 };

    types.b.len = sizeof(bytes);
    types.b.data = bytes;
    types.s = "test";
    types.u32 = 1;
    types.u64 = 2;
    types.s32= -1;
    types.s64 = -2;
    types.f = 1.5f;
    types.d = 3.5f;
    types.e = TEST_ENUM__ONE;

    assert_success(cpn_protobuf_to_string(&buf, 0, &types.base));
    assert_string_equal(buf.data,
            "b: \\001\\002\\003\\004\n"
            "s: test\n"
            "u32: 1\n"
            "u64: 2\n"
            "s32: -1\n"
            "s64: -2\n"
            "f: 1.5\n"
            "d: 3.5\n"
            "e: ONE\n");
}

static void arrays_to_string_succeeds()
{
    TestArrays arrays = TEST_ARRAYS__INIT;
    uint8_t bytes[2][4] = {
        { 0x01, 0x02, 0x03, 0x04 },
        { 0x05, 0x06, 0x07, 0x08 }
    };
    char *strings[] = { "test", "bla" };
    uint32_t u32[] = { 1, 2 };
    uint64_t u64[] = { 3, 4 };
    int32_t s32[] = { -1, -2 };
    int64_t s64[] = { -3, -4 };
    float f[] = { 1.5, 3.5 };
    double d[] = { 4.5, 6.5 };
    TestEnum e[] = { TEST_ENUM__ONE, TEST_ENUM__TWO };

    arrays.n_b = 2;
    arrays.b = malloc(sizeof(ProtobufCBinaryData) * 2);
    arrays.b[0].data = bytes[0];
    arrays.b[0].len = 4;
    arrays.b[1].data = bytes[1];
    arrays.b[1].len = 4;
    arrays.n_s = 2;
    arrays.s = strings;
    arrays.n_u32 = 2;
    arrays.u32 = u32;
    arrays.n_u64 = 2;
    arrays.u64 = u64;
    arrays.n_s32 = 2;
    arrays.s32 = s32;
    arrays.n_s64 = 2;
    arrays.s64 = s64;
    arrays.n_f = 2;
    arrays.f = f;
    arrays.n_d = 2;
    arrays.d = d;
    arrays.n_e = 2;
    arrays.e = e;

    assert_success(cpn_protobuf_to_string(&buf, 0, &arrays.base));
    assert_string_equal(buf.data,
            "b: \\001\\002\\003\\004\n"
            "b: \\005\\006\\007\\010\n"
            "s: test\n"
            "s: bla\n"
            "u32: 1\n"
            "u32: 2\n"
            "u64: 3\n"
            "u64: 4\n"
            "s32: -1\n"
            "s32: -2\n"
            "s64: -3\n"
            "s64: -4\n"
            "f: 1.5\n"
            "f: 3.5\n"
            "d: 4.5\n"
            "d: 6.5\n"
            "e: ONE\n"
            "e: TWO\n");

    free(arrays.b);
}

static void special_chars_to_string_succeeds()
{
    TestParams params = TEST_PARAMS__INIT;
    params.msg = "\\\t\n\r'\"";
    assert_success(cpn_protobuf_to_string(&buf, 0, &params.base));
    assert_string_equal(buf.data, "msg: \\\\\\t\\n\\r\\'\\\"\n");
}

int protobuf_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(empty_protobuf_to_string_succeeds),
        test(protobuf_with_fields_to_string_set_succeeds),
        test(indented_protobuf_to_string_succeeds),
        test(nested_protobuf_to_string_succeeds),
        test(types_to_string_succeeds),
        test(arrays_to_string_succeeds),
        test(special_chars_to_string_succeeds)
    };

    return execute_test_suite("protobuf", tests, setup, teardown);
}
