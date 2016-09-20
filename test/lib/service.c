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
#include "capone/service.h"

#include "test.h"

static struct cpn_cfg cfg;
static struct cpn_service service;

static int setup()
{
    return 0;
}

static int teardown()
{
    cpn_cfg_free(&cfg);
    cpn_service_free(&service);
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

    assert_success(cpn_cfg_parse_string(&cfg, service_config, strlen(service_config)));
    assert_success(cpn_service_from_config(&service, "foo", &cfg));

    /* Assert values */
    assert_string_equal(service.name, "foo");
    assert_string_equal(service.location, "space");
    assert_int_equal(service.port, 7777);

    /* Check plugin pointers */
    assert_string_equal(service.plugin->type, "exec");
    assert_string_equal(service.plugin->category, "Shell");
    assert_non_null(service.plugin->server_fn);
    assert_non_null(service.plugin->client_fn);
    assert_non_null(service.plugin->version);
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

    assert_success(cpn_cfg_parse_string(&cfg, service_config, strlen(service_config)));
    assert_failure(cpn_service_from_config(&service, "foo", &cfg));
}

static void test_incomplete_service_from_config_fails()
{
    static char *service_config =
        "[service]\n"
        "name=foo\n"
        "location=space\n"
        "port=7777\n";

    assert_success(cpn_cfg_parse_string(&cfg, service_config, strlen(service_config)));
    assert_failure(cpn_service_from_config(&service, "foo", &cfg));
}

static void test_services_from_config()
{
    struct cpn_service *services;

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

    assert_success(cpn_cfg_parse_string(&cfg, service_config, strlen(service_config)));
    assert_int_equal(cpn_services_from_config(&services, &cfg), 2);

    assert_string_equal(services[0].name, "foo");
    assert_string_equal(services[1].name, "bar");

    cpn_service_free(&services[0]);
    cpn_service_free(&services[1]);
    free(services);
}

int service_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(test_service_from_config),
        test(test_invalid_service_from_config_fails),
        test(test_incomplete_service_from_config_fails),
        test(test_services_from_config),
    };

    cpn_service_plugin_register_builtins();

    return execute_test_suite("service", tests, setup, teardown);
}
