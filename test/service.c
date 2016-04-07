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
#include "lib/service.h"

#include "test.h"

static struct cfg cfg;
static struct sd_service service;

static const char *single_value[] = {
    "foo"
};

static const char *multiple_values[] = {
    "foo", "bar", "baz",
};

static int setup()
{
    return 0;
}

static int teardown()
{
    cfg_free(&cfg);
    sd_service_free(&service);
    return 0;
}

static void test_service_from_config()
{
    static char *service_config =
        "[service]\n"
        "name=foo\n"
        "type=exec\n"
        "location=space\n"
        "port=7777\n";

    assert_success(cfg_parse_string(&cfg, service_config, strlen(service_config)));
    assert_success(sd_service_from_config(&service, "foo", &cfg));

    /* Assert values */
    assert_string_equal(service.name, "foo");
    assert_string_equal(service.type, "exec");
    assert_string_equal(service.category, "Shell");
    assert_string_equal(service.location, "space");
    assert_string_equal(service.port, "7777");

    /* Check function pointers */
    assert_non_null(service.handle);
    assert_non_null(service.invoke);
    assert_non_null(service.parameters);
    assert_non_null(service.version);
}

static void test_invalid_service_from_config_fails()
{
    static char *service_config =
        "[service]\n"
        "name=foo\n"
        "type=exec\n"
        "location=space\n"
        "port=7777\n"
        "invalidparameter=invalidvalue";

    assert_success(cfg_parse_string(&cfg, service_config, strlen(service_config)));
    assert_failure(sd_service_from_config(&service, "foo", &cfg));
}

static void test_incomplete_service_from_config_fails()
{
    static char *service_config =
        "[service]\n"
        "name=foo\n"
        "location=space\n"
        "port=7777\n";

    assert_success(cfg_parse_string(&cfg, service_config, strlen(service_config)));
    assert_failure(sd_service_from_config(&service, "foo", &cfg));
}

static void test_services_from_config()
{
    struct sd_service *services;

    static char *service_config =
        "[service]\n"
        "name=foo\n"
        "type=exec\n"
        "location=space\n"
        "port=7777\n"
        "\n"
        "[service]\n"
        "name=bar\n"
        "type=xpra\n"
        "location=space\n"
        "port=8888";

    assert_success(cfg_parse_string(&cfg, service_config, strlen(service_config)));
    assert_int_equal(sd_services_from_config(&services, &cfg), 2);

    assert_string_equal(services[0].name, "foo");
    assert_string_equal(services[1].name, "bar");

    sd_service_free(&services[0]);
    sd_service_free(&services[1]);
    free(services);
}

static void test_getting_single_value()
{
    struct sd_service_parameter parameters[] = {
        { "arg", ARRAY_SIZE(single_value), single_value },
    };
    const char *value;

    assert_success(sd_service_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_string_equal(value, single_value[0]);
}

static void test_getting_single_value_with_different_params()
{
    struct sd_service_parameter parameters[] = {
        { "xvlc", 0, NULL },
        { "arg", ARRAY_SIZE(single_value), single_value },
    };
    const char *value;

    assert_success(sd_service_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_string_equal(value, single_value[0]);
}

static void test_getting_value_for_parameter_with_zero_values_fails()
{
    struct sd_service_parameter parameters[] = {
        { "arg", 0, NULL },
    };
    const char *value;

    assert_failure(sd_service_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_null(value);
}

static void test_getting_single_value_for_multiple_available_fails_with_multiple_values()
{
    struct sd_service_parameter parameters[] = {
        { "arg", ARRAY_SIZE(multiple_values), multiple_values },
    };
    const char *value;

    assert_failure(sd_service_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_null(value);
}

static void test_getting_single_value_for_multiple_available_fails_with_multiple_args()
{
    struct sd_service_parameter parameters[] = {
        { "arg", ARRAY_SIZE(single_value), single_value },
        { "arg", ARRAY_SIZE(single_value), single_value },
    };
    const char *value;

    assert_failure(sd_service_parameters_get_value(&value,
                "arg", parameters, ARRAY_SIZE(parameters)));
    assert_null(value);
}

static void test_getting_multiple_values_with_one_result()
{
    struct sd_service_parameter parameters[] = {
        { "arg", ARRAY_SIZE(single_value), single_value },
    };
    const char **values;

    assert_int_equal(sd_service_parameters_get_values(&values,
                "arg", parameters, ARRAY_SIZE(parameters)), 1);
    assert_string_equal(values[0], single_value[0]);

    free(values);
}

static void test_getting_multiple_values_with_multiple_args()
{
    struct sd_service_parameter parameters[] = {
        { "arg", ARRAY_SIZE(single_value), single_value },
        { "arg", ARRAY_SIZE(single_value), single_value },
    };
    const char **values;

    assert_int_equal(sd_service_parameters_get_values(&values,
                "arg", parameters, ARRAY_SIZE(parameters)), 2);
    assert_string_equal(values[0], single_value[0]);
    assert_string_equal(values[1], single_value[0]);

    free(values);
}

static void test_getting_multiple_values_with_multiple_values()
{
    struct sd_service_parameter parameters[] = {
        { "arg", ARRAY_SIZE(multiple_values), multiple_values },
    };
    const char **values;
    size_t i;

    assert_int_equal(sd_service_parameters_get_values(&values,
                "arg", parameters, ARRAY_SIZE(parameters)), ARRAY_SIZE(multiple_values));

    for (i = 0; i < ARRAY_SIZE(multiple_values); i++) {
        assert_string_equal(values[i], multiple_values[i]);
    }

    free(values);
}

static void test_getting_multiple_values_with_multiple_values_and_args()
{
    struct sd_service_parameter parameters[] = {
        { "arg", ARRAY_SIZE(multiple_values), multiple_values },
        { "arg", ARRAY_SIZE(single_value), single_value },
    };
    const char **values;
    size_t i;

    assert_int_equal(sd_service_parameters_get_values(&values,
                "arg", parameters, ARRAY_SIZE(parameters)),
            ARRAY_SIZE(multiple_values) + ARRAY_SIZE(single_value));

    for (i = 0; i < ARRAY_SIZE(multiple_values); i++) {
        assert_string_equal(values[i], multiple_values[i]);
    }
    assert_string_equal(values[ARRAY_SIZE(multiple_values)], single_value[0]);

    free(values);
}

int service_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(test_service_from_config),
        test(test_invalid_service_from_config_fails),
        test(test_incomplete_service_from_config_fails),
        test(test_services_from_config),

        test(test_getting_single_value),
        test(test_getting_single_value_with_different_params),
        test(test_getting_value_for_parameter_with_zero_values_fails),
        test(test_getting_single_value_for_multiple_available_fails_with_multiple_values),
        test(test_getting_single_value_for_multiple_available_fails_with_multiple_args),

        test(test_getting_multiple_values_with_one_result),
        test(test_getting_multiple_values_with_multiple_args),
        test(test_getting_multiple_values_with_multiple_values),
        test(test_getting_multiple_values_with_multiple_values_and_args),
    };

    return execute_test_suite("service", tests, setup, teardown);
}
