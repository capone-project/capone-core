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

#include "test.h"

#include "capone/cmdparse.h"
#include "capone/common.h"

static int setup()
{
    return 0;
}

static int teardown()
{
    return 0;
}

static void parsing_nothing_succeeds()
{
    struct cpn_cmdparse_opt opts[] = { CPN_CMDPARSE_OPT_END };
    assert_success(cpn_cmdparse_parse(opts, 0, NULL));
}

static void parsing_with_no_opts_fails()
{
    struct cpn_cmdparse_opt opts[] = { CPN_CMDPARSE_OPT_END };
    const char *args[] = {
        "--test", "value"
    };

    assert_failure(cpn_cmdparse_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_opt_without_arg_fails()
{
    struct cpn_cmdparse_opt opts[] = { CPN_CMDPARSE_OPT_END };
    const char *args[] = {
        "--test"
    };

    assert_failure(cpn_cmdparse_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_opt_with_arg_succeeds()
{
    struct cpn_cmdparse_opt opts[] = {
        CPN_CMDPARSE_OPT_STRING(0, "--test", false),
        CPN_CMDPARSE_OPT_END
    };
    const char *args[] = {
        "--test", "value"
    };

    assert_success(cpn_cmdparse_parse(opts, ARRAY_SIZE(args), args));
    assert_string_equal(opts[0].value.string, "value");
}

static void parsing_opt_without_argument_fails()
{
    struct cpn_cmdparse_opt opts[] = {
        CPN_CMDPARSE_OPT_STRING(0, "--test", false),
        CPN_CMDPARSE_OPT_END
    };
    const char *args[] = {
        "--test"
    };

    assert_failure(cpn_cmdparse_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_with_unset_optional_arg_succeeds()
{
    struct cpn_cmdparse_opt opts[] = {
        CPN_CMDPARSE_OPT_STRING(0, "--test", false),
        CPN_CMDPARSE_OPT_STRING(0, "--other", true),
        CPN_CMDPARSE_OPT_END
    };
    const char *args[] = {
        "--test", "value"
    };

    assert_success(cpn_cmdparse_parse(opts, ARRAY_SIZE(args), args));
    assert_string_equal(opts[0].value.string, "value");
}

static void parsing_multiple_args_succeeds()
{
    struct cpn_cmdparse_opt opts[] = {
        CPN_CMDPARSE_OPT_STRING(0, "--test", false),
        CPN_CMDPARSE_OPT_STRING(0, "--other", false),
        CPN_CMDPARSE_OPT_END
    };
    const char *args[] = {
        "--test", "value",
        "--other", "other-value"
    };

    assert_success(cpn_cmdparse_parse(opts, ARRAY_SIZE(args), args));
    assert_string_equal(opts[0].value.string, "value");
    assert_string_equal(opts[1].value.string, "other-value");
}

static void parsing_short_arg_succeeds()
{
    struct cpn_cmdparse_opt opts[] = {
        CPN_CMDPARSE_OPT_STRING('t', NULL, false),
        CPN_CMDPARSE_OPT_END
    };
    const char *args[] = {
        "-t", "value",
    };

    assert_success(cpn_cmdparse_parse(opts, ARRAY_SIZE(args), args));
    assert_string_equal(opts[0].value.string, "value");
}

int cmdparse_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(parsing_nothing_succeeds),
        test(parsing_with_no_opts_fails),
        test(parsing_opt_without_arg_fails),
        test(parsing_opt_with_arg_succeeds),
        test(parsing_opt_without_argument_fails),
        test(parsing_with_unset_optional_arg_succeeds),
        test(parsing_multiple_args_succeeds),
        test(parsing_short_arg_succeeds)
    };

    return execute_test_suite("cmdparse", tests, setup, teardown);
}
