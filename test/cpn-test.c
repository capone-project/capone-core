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
#include "capone/opts.h"

#include "test.h"

extern int acl_test_run_suite(void);
extern int buf_test_run_suite(void);
extern int caps_test_run_suite(void);
extern int cfg_test_run_suite(void);
extern int channel_test_run_suite(void);
extern int cmdparse_test_run_suite(void);
extern int common_test_run_suite(void);
extern int global_test_run_suite(void);
extern int keys_test_run_suite(void);
extern int list_test_run_suite(void);
extern int proto_test_run_suite(void);
extern int protobuf_test_run_suite(void);
extern int socket_test_run_suite(void);
extern int service_test_run_suite(void);
extern int session_test_run_suite(void);

extern int capabilities_service_test_run_suite(void);
extern int exec_service_test_run_suite(void);
extern int invoke_service_test_run_suite(void);

static struct cpn_opt opts[] = {
    CPN_OPTS_OPT_COUNTER('v', "--verbose", NULL),
    CPN_OPTS_OPT_END
};

static int (*suite_fns[])(void) = {
    acl_test_run_suite,
    buf_test_run_suite,
    caps_test_run_suite,
    cfg_test_run_suite,
    channel_test_run_suite,
    cmdparse_test_run_suite,
    common_test_run_suite,
    global_test_run_suite,
    keys_test_run_suite,
    list_test_run_suite,
    socket_test_run_suite,
    service_test_run_suite,
    session_test_run_suite,
    proto_test_run_suite,
    protobuf_test_run_suite,

    capabilities_service_test_run_suite,
    exec_service_test_run_suite,
    invoke_service_test_run_suite
};

int main(int argc, const char *argv[])
{
    size_t i, failed, failed_tests = 0, failed_suites = 0;

    if (cpn_opts_parse_cmd(opts, argc, argv) < 0)
        return -1;

    if (opts[0].value.counter == 0)
        cpn_log_set_level(LOG_LEVEL_NONE);
    else if (opts[0].value.counter == 1)
        cpn_log_set_level(LOG_LEVEL_VERBOSE);
    else if (opts[0].value.counter >= 2)
        cpn_log_set_level(LOG_LEVEL_TRACE);

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

    return !!failed_tests;
}
