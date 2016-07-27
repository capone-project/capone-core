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
#include "capone/log.h"

#include "test/test.h"

extern int acl_test_run_suite(void);
extern int caps_test_run_suite(void);
extern int cfg_test_run_suite(void);
extern int channel_test_run_suite(void);
extern int common_test_run_suite(void);
extern int keys_test_run_suite(void);
extern int proto_test_run_suite(void);
extern int server_test_run_suite(void);
extern int service_test_run_suite(void);
extern int session_test_run_suite(void);
extern int parameter_test_run_suite(void);

static int (*suite_fns[])(void) = {
    acl_test_run_suite,
    caps_test_run_suite,
    cfg_test_run_suite,
    channel_test_run_suite,
    common_test_run_suite,
    keys_test_run_suite,
    server_test_run_suite,
    service_test_run_suite,
    session_test_run_suite,
    proto_test_run_suite,
    parameter_test_run_suite
};

int main(int argc, char *argv[])
{
    size_t i, failed, failed_tests = 0, failed_suites = 0;

    if (argc != 1 && (argc == 2 && strcmp(argv[1], "--verbose"))) {
        printf("USAGE: %s [--verbose]", argv[0]);
        return -1;
    }

    if (argc == 2 && !strcmp(argv[1], "--verbose"))
        cpn_log_set_level(LOG_LEVEL_VERBOSE);
    else
        cpn_log_set_level(LOG_LEVEL_NONE);

    for (i = 0; i < ARRAY_SIZE(suite_fns); i++) {
        failed = suite_fns[i]();

        if (failed != 0) {
            failed_tests += failed;
            failed_suites++;
        }
    }

    if (failed_suites) {
        printf("[========]\n[  FAILED  ] %lu/%lu test suite(s) failed\n",
                failed_suites, ARRAY_SIZE(suite_fns));
        printf("[  FAILED  ] %lu test(s) failed\n", failed_tests);
    }

    return 0;
}

int _execute_test_suite(const char *name, const struct CMUnitTest *tests, const size_t count,
        CMFixtureFunction setup, CMFixtureFunction teardown)
{
    printf("[==========] Running testsuite %s\n", name);
    return _cmocka_run_group_tests(name, tests, count, setup, teardown);
}
