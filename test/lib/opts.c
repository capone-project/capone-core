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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "test.h"

#include "capone/common.h"
#include "capone/opts.h"

static FILE *open_tmp(void)
{
    char file[] = "capone-opts.XXXXXX";
    int fd;
    FILE *out;
    mode_t mode;

    mode = umask(0600);
    fd = mkstemp(file);
    assert(fd >= 0);
    out = fdopen(fd, "w+");
    assert_non_null(out);
    umask(mode);
    assert_success(unlink(file));

    return out;
}

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
    struct cpn_opt opts[] = { CPN_OPTS_OPT_END };
    assert_success(cpn_opts_parse(opts, 0, NULL));
}

static void parsing_with_no_opts_fails()
{
    struct cpn_opt opts[] = { CPN_OPTS_OPT_END };
    const char *args[] = {
        "--test", "value"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_opt_without_arg_fails()
{
    struct cpn_opt opts[] = { CPN_OPTS_OPT_END };
    const char *args[] = {
        "--test"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_with_invalid_option_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING(0, "--option", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--misspelled"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_with_unset_required_opt_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING(0, "--option", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };

    assert_failure(cpn_opts_parse(opts, 0, NULL));
}

static void parsing_with_null_opts_succeeds_without_args()
{
    assert_success(cpn_opts_parse(NULL, 0, NULL));
}

static void parsing_with_null_opts_fails_with_args()
{
    const char *args[] = {
        "--misspelled"
    };

    assert_failure(cpn_opts_parse(NULL, ARRAY_SIZE(args), args));
}

static void parsing_opt_with_arg_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING(0, "--test", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--test", "value"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_string_equal(opts[0].value.string, "value");
}

static void parsing_opt_without_argument_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING(0, "--test", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--test"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_with_unset_optional_arg_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING(0, "--test", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--other", NULL, NULL, true),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--test", "value"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_string_equal(opts[0].value.string, "value");
}

static void parsing_multiple_args_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING(0, "--test", NULL, NULL, false),
        CPN_OPTS_OPT_STRING(0, "--other", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--test", "value",
        "--other", "other-value"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_string_equal(opts[0].value.string, "value");
    assert_string_equal(opts[1].value.string, "other-value");
}

static void parsing_short_arg_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('t', NULL, NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "-t", "value",
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_string_equal(opts[0].value.string, "value");
}

static void parsing_action_succeeds()
{
    static struct cpn_opt action_opts[] = {
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_ACTION("action", NULL, action_opts),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "action"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_true(opts[0].set);
}

static void parsing_action_with_additional_args_succeeds()
{
    static struct cpn_opt action_opts[] = {
        CPN_OPTS_OPT_STRING(0, "--test", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_ACTION("action", NULL, action_opts),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "action",
        "--test", "value"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_true(opts[0].set);
    assert_string_equal(action_opts[0].value.string, "value");
}

static void parsing_action_with_duplicated_args_succeeds()
{
    static struct cpn_opt action_opts[] = {
        CPN_OPTS_OPT_STRING(0, "--test", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING(0, "--test", NULL, NULL, false),
        CPN_OPTS_OPT_ACTION("action", NULL, action_opts),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--test", "general-value",
        "action",
        "--test", "action-value"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_string_equal(opts[0].value.string, "general-value");
    assert_true(opts[1].set);
    assert_string_equal(action_opts[0].value.string, "action-value");
}

static void parsing_action_with_general_arg_fails()
{
    static struct cpn_opt action_opts[] = {
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_ACTION("action", NULL, action_opts),
        CPN_OPTS_OPT_STRING(0, "--test", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "action",
        "--test", "action-value"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_multiple_actions_fails()
{
    static struct cpn_opt action_opts[] = {
        CPN_OPTS_OPT_END
    };
    static struct cpn_opt other_opts[] = {
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_ACTION("action", NULL, action_opts),
        CPN_OPTS_OPT_ACTION("other", NULL, other_opts),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "action", "other"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_multiple_actions_with_wrong_args_fails()
{
    static struct cpn_opt action_opts[] = {
        CPN_OPTS_OPT_END
    };
    static struct cpn_opt other_opts[] = {
        CPN_OPTS_OPT_STRING(0, "--test", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_ACTION("action", NULL, action_opts),
        CPN_OPTS_OPT_ACTION("other", NULL, other_opts),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "action",
        "--test", "action-value"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_uint32_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_UINT32(0, "--uint32", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--uint32", "12345"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_int_equal(opts[0].value.uint32, 12345);
}

static void parsing_zero_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_UINT32(0, "--uint32", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--uint32", "0"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_int_equal(opts[0].value.uint32, 0);
}

static void parsing_uint32_without_argument_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_UINT32(0, "--uint32", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--uint32"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_negative_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_UINT32(0, "--uint32", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--uint32", "-1"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_int_with_garbage_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_UINT32(0, "--uint32", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--uint32", "12345garbage"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_sigkey_succeeds()
{
    static const char hex[] =
        "5178f420aaf894d36fd28a8e72681b37"
        "7db14fc9e47a7eb51afe1a2905a45e55";
    static struct cpn_sign_key_public pk;
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_SIGKEY(0, "--key", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = { "--key", hex };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_success(cpn_sign_key_public_from_hex(&pk, hex));
    assert_memory_equal(&pk, &opts[0].value.sigkey, sizeof(pk));
}

static void parsing_sigkey_with_wrong_length_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_SIGKEY(0, "--key", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--key", "5178f420aaf894d36fd28a8e72681b377db14fc9e47a7eb51afe"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_sigkey_with_non_hex_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_SIGKEY(0, "--key", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--key", "zzzzz420aaf894d36fd28a8e72681b377db14fc9e47a7eb51afe1a2905a45e55"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_sigkey_without_argument_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_SIGKEY(0, "--key", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--key"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void parsing_counter_without_increments_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_COUNTER('i', "--increment", NULL),
        CPN_OPTS_OPT_END
    };

    assert_success(cpn_opts_parse(opts, 0, NULL));
    assert_int_equal(opts[0].value.counter, 0);
}

static void parsing_counter_with_single_increment_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_COUNTER('i', "--increment", NULL),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "-i"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_int_equal(opts[0].value.counter, 1);
}

static void parsing_counter_with_multiple_increments_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_COUNTER('i', "--increment", NULL),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "-i", "-i", "-i"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_int_equal(opts[0].value.counter, 3);
}

static void parsing_counter_with_mixed_increments_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_COUNTER('i', "--increment", NULL),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "-i", "--increment", "-i", "--increment"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_int_equal(opts[0].value.counter, 4);
}

static void parsing_stringlist_with_single_argument_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRINGLIST(0, "--list", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--list", "value"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_int_equal(opts[0].value.stringlist.argc, 1);
    assert_string_equal(opts[0].value.stringlist.argv[0], "value");
}

static void parsing_stringlist_with_multiple_arguments_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRINGLIST(0, "--list", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--list", "value", "other-value", "third-value"
    };

    assert_success(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
    assert_int_equal(opts[0].value.stringlist.argc, 3);
    assert_string_equal(opts[0].value.stringlist.argv[0], "value");
    assert_string_equal(opts[0].value.stringlist.argv[1], "other-value");
    assert_string_equal(opts[0].value.stringlist.argv[2], "third-value");
}

static void parsing_stringlist_without_arguments_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRINGLIST(0, "--list", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    const char *args[] = {
        "--list"
    };

    assert_failure(cpn_opts_parse(opts, ARRAY_SIZE(args), args));
}

static void getting_value_on_empty_opts_returns_nothing()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_END
    };

    assert_null(cpn_opts_get(opts, 'c', NULL));
    assert_null(cpn_opts_get(opts, 'c', "--config"));
    assert_null(cpn_opts_get(opts, 0, "--config"));
}

static void getting_single_value_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('s', "--string", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };

    opts[0].set = 1;
    opts[0].value.string = "value";

    assert_string_equal(cpn_opts_get(opts, 's', NULL)->string, "value");
    assert_string_equal(cpn_opts_get(opts, 0, "--string")->string, "value");
}

static void getting_value_with_mixed_short_and_long_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('s', "--string", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };

    opts[0].set = 1;
    opts[0].value.string = "value";

    assert_null(cpn_opts_get(opts, 's', "--wrong-long-name"));
    assert_null(cpn_opts_get(opts, 'f', "--string"));
}

static void getting_value_with_unset_option_fails()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('s', "--string", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };

    assert_null(cpn_opts_get(opts, 's', NULL));
    assert_null(cpn_opts_get(opts, 0, "--string"));
}

static void getting_value_with_multiple_options_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('s', "--string", NULL, NULL, false),
        CPN_OPTS_OPT_STRING('o', "--other", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };

    opts[0].set = 1;
    opts[0].value.string = "value";
    opts[1].set = 1;
    opts[1].value.string = "other";

    assert_string_equal(cpn_opts_get(opts, 's', NULL)->string, "value");
    assert_string_equal(cpn_opts_get(opts, 'o', NULL)->string, "other");
}

static void getting_unset_option_with_multiple_options_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('s', "--string", NULL, NULL, false),
        CPN_OPTS_OPT_STRING('o', "--other", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };

    opts[1].set = 1;
    opts[1].value.string = "other";

    assert_null(cpn_opts_get(opts, 's', NULL));
}

static void usage_with_no_opts_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_END
    };
    FILE *out = open_tmp();

    cpn_opts_usage(opts, "test", out);

    assert_file_equal(out, "USAGE: test\n");
}

static void usage_with_single_opt_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('s', "--string", "This is a string", "STRING", false),
        CPN_OPTS_OPT_END
    };
    FILE *out = open_tmp();

    cpn_opts_usage(opts, "test", out);

    assert_file_equal(out,
            "USAGE: test [OPTIONS...]\n"
            "\n"
            "\t-s, --string <STRING>\n"
            "\t\tThis is a string\n");
}

static void usage_with_multiple_opts_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('s', "--string", "This is a string", "STRING", false),
        CPN_OPTS_OPT_STRING('o', "--other", NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    FILE *out = open_tmp();

    cpn_opts_usage(opts, "test", out);

    assert_file_equal(out,
            "USAGE: test [OPTIONS...]\n"
            "\n"
            "\t-s, --string <STRING>\n"
            "\t\tThis is a string\n"
            "\t-o, --other <VALUE>\n");
}

static void usage_with_all_option_types_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_COUNTER('c', "--counter", "Count"),
        CPN_OPTS_OPT_SIGKEY('k', "--sigkey", "Signature key", "SIGKEY", false),
        CPN_OPTS_OPT_STRING('s', "--string", "This is a string", "STRING", false),
        CPN_OPTS_OPT_STRINGLIST('l', "--stringlist", "This is a list of strings", "STRINGS", false),
        CPN_OPTS_OPT_UINT32('u', "--uint32", "Unsigned integer", "UINT32", false),
        CPN_OPTS_OPT_END
    };
    FILE *out = open_tmp();

    cpn_opts_usage(opts, "test", out);

    assert_file_equal(out,
            "USAGE: test [OPTIONS...]\n"
            "\n"
            "\t-c, --counter\n"
            "\t\tCount\n"
            "\t-k, --sigkey <SIGKEY>\n"
            "\t\tSignature key\n"
            "\t-s, --string <STRING>\n"
            "\t\tThis is a string\n"
            "\t-l, --stringlist [STRINGS...]\n"
            "\t\tThis is a list of strings\n"
            "\t-u, --uint32 <UINT32>\n"
            "\t\tUnsigned integer\n");
}

static void usage_with_mixed_short_and_long_opts_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING(0, "--string", "This is a string", "STRING", false),
        CPN_OPTS_OPT_STRING('o', NULL, NULL, NULL, false),
        CPN_OPTS_OPT_END
    };
    FILE *out = open_tmp();

    cpn_opts_usage(opts, "test", out);

    assert_file_equal(out,
            "USAGE: test [OPTIONS...]\n"
            "\n"
            "\t--string <STRING>\n"
            "\t\tThis is a string\n"
            "\t-o <VALUE>\n");
}

static void usage_with_single_action_without_args_succeeds()
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_ACTION("action", "This is an action", NULL),
        CPN_OPTS_OPT_END
    };
    FILE *out = open_tmp();

    cpn_opts_usage(opts, "test", out);

    assert_file_equal(out,
            "USAGE: test (action)\n"
            "\n"
            "\taction: This is an action\n");
}

static void usage_with_single_action_with_args_succeeds()
{
    static struct cpn_opt action_opts[] = {
        CPN_OPTS_OPT_STRING('s', "--string", "This is a string", "STRING", false),
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_ACTION("action", "This is an action", action_opts),
        CPN_OPTS_OPT_END
    };
    FILE *out = open_tmp();

    cpn_opts_usage(opts, "test", out);

    assert_file_equal(out,
            "USAGE: test (action)\n"
            "\n"
            "\taction [OPTIONS...]: This is an action\n"
            "\t\t-s, --string <STRING>\n"
            "\t\t\tThis is a string\n");
}

static void usage_with_single_action_and_global_args()
{
    static struct cpn_opt action_opts[] = {
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('s', "--string", "This is a string", "STRING", false),
        CPN_OPTS_OPT_ACTION("action", "This is an action", action_opts),
        CPN_OPTS_OPT_END
    };
    FILE *out = open_tmp();

    cpn_opts_usage(opts, "test", out);

    assert_file_equal(out,
            "USAGE: test [OPTIONS...] (action)\n"
            "\n"
            "\t-s, --string <STRING>\n"
            "\t\tThis is a string\n"
            "\n"
            "\taction: This is an action\n");
}

static void usage_with_multiple_actions_and_arguments()
{
    static struct cpn_opt action_opts[] = {
        CPN_OPTS_OPT_END
    };
    static struct cpn_opt other_opts[] = {
        CPN_OPTS_OPT_STRING('o', "--other", "Other description", "O", false),
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('g', "--global", "This is a global string", "STRING", false),
        CPN_OPTS_OPT_ACTION("action", "This is an action", action_opts),
        CPN_OPTS_OPT_ACTION("other", "This is another action", other_opts),
        CPN_OPTS_OPT_END
    };
    FILE *out = open_tmp();

    cpn_opts_usage(opts, "test", out);

    assert_file_equal(out,
            "USAGE: test [OPTIONS...] (action|other)\n"
            "\n"
            "\t-g, --global <STRING>\n"
            "\t\tThis is a global string\n"
            "\n"
            "\taction: This is an action\n"
            "\tother [OPTIONS...]: This is another action\n"
            "\t\t-o, --other <O>\n"
            "\t\t\tOther description\n");
}

static void usage_with_subsubactions()
{
    static struct cpn_opt subaction_opts[] = {
        CPN_OPTS_OPT_END
    };
    static struct cpn_opt action_opts[] = {
        CPN_OPTS_OPT_STRING('o', "--other", "Other description", "O", false),
        CPN_OPTS_OPT_ACTION("subaction", "This is a subaction", subaction_opts),
        CPN_OPTS_OPT_END
    };
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('g', "--global", "This is a global string", "STRING", false),
        CPN_OPTS_OPT_ACTION("action", "This is an action", action_opts),
        CPN_OPTS_OPT_END
    };
    FILE *out = open_tmp();

    cpn_opts_usage(opts, "test", out);

    assert_file_equal(out,
            "USAGE: test [OPTIONS...] (action)\n"
            "\n"
            "\t-g, --global <STRING>\n"
            "\t\tThis is a global string\n"
            "\n"
            "\taction [OPTIONS...] (subaction): This is an action\n"
            "\t\t-o, --other <O>\n"
            "\t\t\tOther description\n"
            "\t\tsubaction: This is a subaction\n");
}

static void version_succeeds()
{
    FILE *out = open_tmp();

    cpn_opts_version("test", out);

    assert_file_equal(out,
            "test " VERSION "\n"
            "Copyright (C) 2016 Patrick Steinhardt\n"
            "License GPLv3: GNU GPL version 3 <http://gnu.org/licenses/gpl.html>.\n"
            "This is free software; you are free to change and redistribute it.\n"
            "There is NO WARRANTY, to the extent permitted by the law.\n");
}

int cmdparse_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(parsing_nothing_succeeds),
        test(parsing_with_no_opts_fails),
        test(parsing_opt_without_arg_fails),
        test(parsing_with_invalid_option_fails),
        test(parsing_with_unset_required_opt_fails),
        test(parsing_with_null_opts_succeeds_without_args),
        test(parsing_with_null_opts_fails_with_args),

        test(parsing_opt_with_arg_succeeds),
        test(parsing_opt_without_argument_fails),
        test(parsing_with_unset_optional_arg_succeeds),
        test(parsing_multiple_args_succeeds),
        test(parsing_short_arg_succeeds),

        test(parsing_action_succeeds),
        test(parsing_action_with_additional_args_succeeds),
        test(parsing_action_with_duplicated_args_succeeds),
        test(parsing_action_with_general_arg_fails),
        test(parsing_multiple_actions_with_wrong_args_fails),
        test(parsing_multiple_actions_fails),

        test(parsing_uint32_succeeds),
        test(parsing_zero_succeeds),
        test(parsing_uint32_without_argument_fails),
        test(parsing_negative_fails),
        test(parsing_int_with_garbage_fails),

        test(parsing_sigkey_succeeds),
        test(parsing_sigkey_with_wrong_length_fails),
        test(parsing_sigkey_with_non_hex_fails),
        test(parsing_sigkey_without_argument_fails),

        test(parsing_counter_without_increments_succeeds),
        test(parsing_counter_with_single_increment_succeeds),
        test(parsing_counter_with_multiple_increments_succeeds),
        test(parsing_counter_with_mixed_increments_succeeds),

        test(parsing_stringlist_with_single_argument_succeeds),
        test(parsing_stringlist_with_multiple_arguments_succeeds),
        test(parsing_stringlist_without_arguments_fails),

        test(getting_value_on_empty_opts_returns_nothing),
        test(getting_single_value_succeeds),
        test(getting_value_with_mixed_short_and_long_fails),
        test(getting_value_with_unset_option_fails),
        test(getting_value_with_multiple_options_succeeds),
        test(getting_unset_option_with_multiple_options_succeeds),

        test(usage_with_no_opts_succeeds),
        test(usage_with_single_opt_succeeds),
        test(usage_with_multiple_opts_succeeds),
        test(usage_with_all_option_types_succeeds),
        test(usage_with_mixed_short_and_long_opts_succeeds),
        test(usage_with_single_action_without_args_succeeds),
        test(usage_with_single_action_with_args_succeeds),
        test(usage_with_single_action_and_global_args),
        test(usage_with_multiple_actions_and_arguments),
        test(usage_with_subsubactions),

        test(version_succeeds)
    };

    return execute_test_suite("cmdparse", tests, setup, teardown);
}
