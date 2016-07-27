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

static struct cpn_parameter *results;
static size_t nresults;

static int setup()
{
    results = NULL;
    nresults = 0;
    return 0;
}

static int teardown()
{
    cpn_parameters_free(results, nresults);
    return 0;
}

static void test_duplicating_parameters()
{
    struct cpn_parameter params[] = {
        { "key1", "value1" },
        { "key2", "value2" },
        { "key2", "value3" },
        { "key3", NULL },
    };
    size_t i;

    nresults = cpn_parameters_dup(&results, params, ARRAY_SIZE(params));
    assert_int_equal(nresults, ARRAY_SIZE(params));

    for (i = 0; i < ARRAY_SIZE(params) - 1; i++) {
        assert_string_equal(params[i].key, results[i].key);
        assert_string_equal(params[i].value, results[i].value);
    }
    assert_string_equal(params[3].key, results[3].key);
    assert_null(results[i].value);
}

static void test_parsing_parameter()
{
    char *args[] = {
        "key=value"
    };

    nresults = cpn_parameters_parse(&results, ARRAY_SIZE(args), args);
    assert_int_equal(nresults, 1);
    assert_string_equal(results[0].key, "key");
    assert_string_equal(results[0].value, "value");
}

static void test_parsing_parameters()
{
    char *args[] = {
        "key1=value1", "key2=value2"
    };

    nresults = cpn_parameters_parse(&results, ARRAY_SIZE(args), args);
    assert_int_equal(nresults, 2);
    assert_string_equal(results[0].key, "key1");
    assert_string_equal(results[0].value, "value1");
    assert_string_equal(results[1].key, "key2");
    assert_string_equal(results[1].value, "value2");
}

static void test_parsing_parameter_with_multiple_equals()
{
    char *args[] = {
        "key=param=value"
    };

    nresults = cpn_parameters_parse(&results, ARRAY_SIZE(args), args);
    assert_int_equal(nresults, 1);
    assert_string_equal(results[0].key, "key");
    assert_string_equal(results[0].value, "param=value");
}

static void test_parsing_parameter_with_no_value()
{
    char *args[] = {
        "key"
    };

    nresults = cpn_parameters_parse(&results, ARRAY_SIZE(args), args);
    assert_int_equal(nresults, 1);
    assert_string_equal(results[0].key, "key");
    assert_null(results[0].value);
}

static void test_parsing_parameter_with_empty_value()
{
    char *args[] = {
        "key="
    };

    nresults = cpn_parameters_parse(&results, ARRAY_SIZE(args), args);
    assert_int_equal(nresults, 1);
    assert_string_equal(results[0].key, "key");
    assert_string_equal(results[0].value, "");
}

static void test_filtering_matching_value()
{
    struct cpn_parameter parameters[] = {
        { "matching", "value" },
    };

    nresults = cpn_parameters_filter(&results, "matching",
            parameters, ARRAY_SIZE(parameters));
    assert_int_equal(nresults, ARRAY_SIZE(parameters));
    assert_string_equal(results[0].key, "matching");
    assert_string_equal(results[0].value, "value");
}

static void test_filtering_matching_values()
{
    struct cpn_parameter parameters[] = {
        { "matching", "value1" },
        { "matching", "value2" },
        { "matching", "value3" },
    };
    size_t i;

    nresults = cpn_parameters_filter(&results, "matching",
            parameters, ARRAY_SIZE(parameters));
    assert_int_equal(nresults, ARRAY_SIZE(parameters));

    for (i = 0; i < ARRAY_SIZE(parameters); i++) {
        assert_string_equal(results[i].key, parameters[i].key);
        assert_string_equal(results[i].value, parameters[i].value);
    }
}

static void test_filtering_nonmatching()
{
    struct cpn_parameter parameters[] = {
        { "nonmatching", "value1" },
        { "nonmatching", "value2" },
        { "nonmatching", "value3" },
    };

    assert_int_equal(cpn_parameters_filter(NULL, "matching",
                parameters, ARRAY_SIZE(parameters)), 0);
}

static void test_filtering_mixed_items()
{
    struct cpn_parameter parameters[] = {
        { "matching", "value1" },
        { "nonmatching", "value2" },
        { "matching", "value3" },
    };

    nresults = cpn_parameters_filter(&results, "matching",
            parameters, ARRAY_SIZE(parameters));
    assert_int_equal(nresults, 2);
    assert_string_equal(results[0].key, parameters[0].key);
    assert_string_equal(results[0].value, parameters[0].value);
    assert_string_equal(results[1].key, parameters[2].key);
    assert_string_equal(results[1].value, parameters[2].value);
}

static void test_getting_single_value()
{
    struct cpn_parameter parameters[] = {
        { "arg", "foo" },
    };
    const char *value;

    assert_success(cpn_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_string_equal(value, parameters[0].value);
}

static void test_getting_single_value_with_different_params()
{
    struct cpn_parameter parameters[] = {
        { "xvlc", "bar" },
        { "arg", "foo" },
    };
    const char *value;

    assert_success(cpn_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_string_equal(value, parameters[1].value);
}

static void test_getting_value_for_parameter_with_zero_values_fails()
{
    struct cpn_parameter parameters[] = {
        { "arg", NULL },
    };
    const char *value;

    assert_failure(cpn_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_null(value);
}

static void test_getting_single_value_for_multiple_available_fails_with_multiple_args()
{
    struct cpn_parameter parameters[] = {
        { "arg", "foo" },
        { "arg", "foo" },
    };
    const char *value;

    assert_failure(cpn_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_null(value);
}

static void test_getting_multiple_values_with_one_result()
{
    struct cpn_parameter parameters[] = {
        { "arg", "foo" },
    };
    const char **values;

    assert_int_equal(cpn_parameters_get_values(&values,
                "arg", parameters, ARRAY_SIZE(parameters)), 1);
    assert_string_equal(values[0], parameters[0].value);

    free(values);
}

static void test_getting_multiple_values_with_multiple_args()
{
    struct cpn_parameter parameters[] = {
        { "arg", "foo" },
        { "arg", "foo" },
    };
    const char **values;

    assert_int_equal(cpn_parameters_get_values(&values,
                "arg", parameters, ARRAY_SIZE(parameters)), 2);
    assert_string_equal(values[0], parameters[0].value);
    assert_string_equal(values[1], parameters[1].value);

    free(values);
}

static void test_converting_parameters()
{
    Parameter **out;
    struct cpn_parameter parameters[] = {
        { "arg1", "val1" },
        { "arg2", "val2" },
        { "arg3", "val3" },
        { "arg4", "val4" },
    };
    size_t i;

    assert_int_equal(cpn_parameters_to_proto(&out, parameters, ARRAY_SIZE(parameters)),
            ARRAY_SIZE(parameters));
    for (i = 0; i < ARRAY_SIZE(parameters); i++) {
        assert_string_equal(out[i]->key, parameters[i].key);
        assert_string_equal(out[i]->value, parameters[i].value);
    }

    cpn_parameters_proto_free(out, ARRAY_SIZE(parameters));
}

static void test_converting_parameters_with_null_values()
{
    Parameter **out;
    struct cpn_parameter parameters[] = {
        { "arg1", NULL },
        { "arg2", NULL },
    };
    size_t i;

    assert_int_equal(cpn_parameters_to_proto(&out, parameters, ARRAY_SIZE(parameters)),
            ARRAY_SIZE(parameters));
    for (i = 0; i < ARRAY_SIZE(parameters); i++) {
        assert_string_equal(out[i]->key, parameters[i].key);
        assert_null(out[i]->value);
    }

    cpn_parameters_proto_free(out, ARRAY_SIZE(parameters));
}

int parameter_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(test_duplicating_parameters),

        test(test_parsing_parameter),
        test(test_parsing_parameters),
        test(test_parsing_parameter_with_multiple_equals),
        test(test_parsing_parameter_with_no_value),
        test(test_parsing_parameter_with_empty_value),

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
