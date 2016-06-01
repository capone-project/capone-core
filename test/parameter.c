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

#include "lib/common.h"
#include "lib/parameter.h"

#include "test.h"

static int setup()
{
    return 0;
}

static int teardown()
{
    return 0;
}

static void test_filtering_matching_value()
{
    struct sd_parameter *out;
    struct sd_parameter parameters[] = {
        { "matching", "value" },
    };

    assert_int_equal(sd_parameters_filter(&out, "matching",
                parameters, ARRAY_SIZE(parameters)), 1);
    assert_string_equal(out[0].key, "matching");
    assert_string_equal(out[0].value, "value");
}

static void test_filtering_matching_values()
{
    struct sd_parameter *out;
    struct sd_parameter parameters[] = {
        { "matching", "value1" },
        { "matching", "value2" },
        { "matching", "value3" },
    };
    size_t i;

    assert_int_equal(sd_parameters_filter(&out, "matching",
                parameters, ARRAY_SIZE(parameters)), 3);

    for (i = 0; i < ARRAY_SIZE(parameters); i++) {
        assert_string_equal(out[i].key, parameters[i].key);
        assert_string_equal(out[i].value, parameters[i].value);
    }
}

static void test_filtering_nonmatching()
{
    struct sd_parameter *out;
    struct sd_parameter parameters[] = {
        { "nonmatching", "value1" },
        { "nonmatching", "value2" },
        { "nonmatching", "value3" },
    };

    assert_int_equal(sd_parameters_filter(&out, "matching",
                parameters, ARRAY_SIZE(parameters)), 0);
}

static void test_filtering_mixed_items()
{
    struct sd_parameter *out;
    struct sd_parameter parameters[] = {
        { "matching", "value1" },
        { "nonmatching", "value2" },
        { "matching", "value3" },
    };

    assert_int_equal(sd_parameters_filter(&out, "matching",
                parameters, ARRAY_SIZE(parameters)), 2);
    assert_string_equal(out[0].key, parameters[0].key);
    assert_string_equal(out[0].value, parameters[0].value);
    assert_string_equal(out[1].key, parameters[2].key);
    assert_string_equal(out[1].value, parameters[2].value);
}

static void test_getting_single_value()
{
    struct sd_parameter parameters[] = {
        { "arg", "foo" },
    };
    const char *value;

    assert_success(sd_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_string_equal(value, parameters[0].value);
}

static void test_getting_single_value_with_different_params()
{
    struct sd_parameter parameters[] = {
        { "xvlc", "bar" },
        { "arg", "foo" },
    };
    const char *value;

    assert_success(sd_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_string_equal(value, parameters[1].value);
}

static void test_getting_value_for_parameter_with_zero_values_fails()
{
    struct sd_parameter parameters[] = {
        { "arg", NULL },
    };
    const char *value;

    assert_failure(sd_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_null(value);
}

static void test_getting_single_value_for_multiple_available_fails_with_multiple_args()
{
    struct sd_parameter parameters[] = {
        { "arg", "foo" },
        { "arg", "foo" },
    };
    const char *value;

    assert_failure(sd_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_null(value);
}

static void test_getting_multiple_values_with_one_result()
{
    struct sd_parameter parameters[] = {
        { "arg", "foo" },
    };
    const char **values;

    assert_int_equal(sd_parameters_get_values(&values,
                "arg", parameters, ARRAY_SIZE(parameters)), 1);
    assert_string_equal(values[0], parameters[0].value);

    free(values);
}

static void test_getting_multiple_values_with_multiple_args()
{
    struct sd_parameter parameters[] = {
        { "arg", "foo" },
        { "arg", "foo" },
    };
    const char **values;

    assert_int_equal(sd_parameters_get_values(&values,
                "arg", parameters, ARRAY_SIZE(parameters)), 2);
    assert_string_equal(values[0], parameters[0].value);
    assert_string_equal(values[1], parameters[1].value);

    free(values);
}

static void test_converting_parameters()
{
    Parameter **out;
    struct sd_parameter parameters[] = {
        { "arg1", "val1" },
        { "arg2", "val2" },
        { "arg3", "val3" },
        { "arg4", "val4" },
    };
    size_t i;

    assert_int_equal(sd_parameters_to_proto(&out, parameters, ARRAY_SIZE(parameters)),
            ARRAY_SIZE(parameters));
    for (i = 0; i < ARRAY_SIZE(parameters); i++) {
        assert_string_equal(out[i]->key, parameters[i].key);
        assert_string_equal(out[i]->value, parameters[i].value);
    }

    sd_parameters_proto_free(out, ARRAY_SIZE(parameters));
}

static void test_converting_parameters_with_null_values()
{
    Parameter **out;
    struct sd_parameter parameters[] = {
        { "arg1", NULL },
        { "arg2", NULL },
    };
    size_t i;

    assert_int_equal(sd_parameters_to_proto(&out, parameters, ARRAY_SIZE(parameters)),
            ARRAY_SIZE(parameters));
    for (i = 0; i < ARRAY_SIZE(parameters); i++) {
        assert_string_equal(out[i]->key, parameters[i].key);
        assert_null(out[i]->value);
    }

    sd_parameters_proto_free(out, ARRAY_SIZE(parameters));
}

int parameter_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(test_filtering_matching_value),
        test(test_filtering_matching_values),
        test(test_filtering_nonmatching),
        test(test_filtering_mixed_items),

        test(test_getting_single_value),
        test(test_getting_single_value_with_different_params),
        test(test_getting_value_for_parameter_with_zero_values_fails),
        test(test_getting_single_value_for_multiple_available_fails_with_multiple_args),
        test(test_getting_multiple_values_with_one_result),
        test(test_getting_multiple_values_with_multiple_args),

        test(test_converting_parameters),
        test(test_converting_parameters_with_null_values)
    };

    return execute_test_suite("parameter", tests, setup, teardown);
}
