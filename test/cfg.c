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

#include "lib/cfg.h"
#include "lib/common.h"

#include "test.h"

#define assert_cfg_section(c, n, expected) do {                     \
        assert_string_equal((c).sections[(n)].name, (expected)); \
    } while (0)
#define assert_cfg_entry(c, section, n, expected_name, expected_value) do {                     \
        assert_string_equal((c).sections[(section)].entries[(n)].name, (expected_name));      \
        assert_string_equal((c).sections[(section)].entries[(n)].value, (expected_value));    \
    } while (0)

static struct cfg config;
static char *value = NULL;

static int setup()
{
    value = NULL;
    return 0;
}

static int teardown()
{
    cfg_free(&config);
    free(value);
    return 0;
}

static void parse_empty()
{
    const char text[] = "";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));
    assert_int_equal(config.sections, 0);
}

static void parse_simple()
{
    const char text[] =
        "[one]\n"
        "two=three";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    assert_int_equal(config.numsections, 1);
    assert_int_equal(config.sections[0].numentries, 1);

    assert_cfg_section(config, 0, "one");
    assert_cfg_entry(config, 0, 0, "two", "three");
}

static void parse_empty_line()
{
    const char text[] =
        "[one]\n"
        "two=three\n"
        "\n"
        "four=five\n";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    assert_int_equal(config.numsections, 1);
    assert_int_equal(config.sections[0].numentries, 2);

    assert_cfg_section(config, 0, "one");
    assert_cfg_entry(config, 0, 0, "two", "three");
    assert_cfg_entry(config, 0, 1, "four", "five");
}

static void parse_multiple_sections()
{
    const char text[] =
        "[one]\n"
        "[two]";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    assert_int_equal(config.numsections, 2);

    assert_cfg_section(config, 0, "one");
    assert_cfg_section(config, 1, "two");

    assert_int_equal(config.sections[0].numentries, 0);
    assert_int_equal(config.sections[1].numentries, 0);
}

static void parse_leading_whitespace()
{
    const char text[] = " \n\t  \t[one]\n";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    assert_int_equal(config.numsections, 1);
    assert_cfg_section(config, 0, "one");
}

static void parse_trailing_whitespace()
{
    const char text[] =
        "[one]\t   \t\n\t\n"
        "[two]";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    assert_int_equal(config.numsections, 2);
    assert_cfg_section(config, 0, "one");
    assert_cfg_section(config, 1, "two");
}

static void parse_invalid_without_section()
{
    const char text[] =
        "one=two";

    assert_failure(cfg_parse_string(&config, text, sizeof(text)));
    assert_int_equal(config.numsections, 0);
}

static void parse_invalid_section_format()
{
    const char text[] =
        "[bla";

    assert_failure(cfg_parse_string(&config, text, sizeof(text)));
    assert_int_equal(config.numsections, 0);
}

static void parse_invalid_missing_assignment()
{
    const char text[] =
        "[one]\n"
        "two three";

    assert_failure(cfg_parse_string(&config, text, sizeof(text)));
    assert_null(config.sections);
    assert_int_equal(config.numsections, 0);
}

static void parse_invalid_missing_value()
{
    const char text[] =
        "[one]\n"
        "two=";

    assert_failure(cfg_parse_string(&config, text, sizeof(text)));
    assert_null(config.sections);
    assert_int_equal(config.numsections, 0);
}

static void get_section_simple()
{
    const struct cfg_section *s;
    const char text[] =
        "[one]\n"
        "two=three";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    s = cfg_get_section(&config, "one");
    assert_non_null(s);
    assert_string_equal(s->name, "one");
}

static void get_section_with_multiple_sections()
{
    const struct cfg_section *s;
    const char text[] =
        "[one]\n"
        "[two]\n"
        "three=four\n"
        "[five]\n";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    s = cfg_get_section(&config, "one");
    assert_non_null(s);
    assert_string_equal(s->name, "one");

    s = cfg_get_section(&config, "two");
    assert_non_null(s);
    assert_string_equal(s->name, "two");

    s = cfg_get_section(&config, "five");
    assert_non_null(s);
    assert_string_equal(s->name, "five");
}

static void get_section_nonexisting()
{
    const struct cfg_section *s;
    const char text[] =
        "[one]\n"
        "two=three";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    s = cfg_get_section(&config, "two");
    assert_null(s);
}

static void get_entry_simple()
{
    const struct cfg_section *s;
    const struct cfg_entry *e;
    const char text[] =
        "[one]\n"
        "two=three";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    s = cfg_get_section(&config, "one");
    assert_non_null(s);

    e = cfg_get_entry(s, "two");
    assert_non_null(e);
    assert_string_equal(e->name, "two");
}

static void get_entry_nonexisting()
{
    const struct cfg_section *s;
    const struct cfg_entry *e;
    const char text[] =
        "[one]\n";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    s = cfg_get_section(&config, "one");
    assert_non_null(s);
    assert_null(e = cfg_get_entry(s, "two"));
}

static void get_str_value_simple()
{
    const char text[] =
        "[one]\n"
        "two=three";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    value = cfg_get_str_value(&config, "one", "two");
    assert_string_equal(value, "three");
}

static void get_str_value_nonexisting()
{
    const char text[] =
        "[one]\n"
        "two=three";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    value = cfg_get_str_value(&config, "four", "five");
    assert_null(value);
}

static void get_int_value_simple()
{
    const char text[] =
        "[one]\n"
        "two=12345";
    int i;

    assert_success(cfg_parse_string(&config, text, sizeof(text)));

    i = cfg_get_int_value(&config, "one", "two");
    assert_int_equal(i, 12345);
}

static void get_int_value_nonexisting()
{
    const char text[] =
        "[one]\n"
        "";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));
    assert_success(cfg_get_int_value(&config, "one", "two"));
}

static void get_int_value_invalid()
{
    const char text[] =
        "[one]\n"
        "two=xvlc";

    assert_success(cfg_parse_string(&config, text, sizeof(text)));
    assert_success(cfg_get_int_value(&config, "one", "two"));
}

int cfg_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(parse_empty),
        test(parse_simple),
        test(parse_empty_line),
        test(parse_multiple_sections),
        test(parse_leading_whitespace),
        test(parse_trailing_whitespace),
        test(parse_invalid_without_section),
        test(parse_invalid_section_format),
        test(parse_invalid_missing_assignment),
        test(parse_invalid_missing_value),

        test(get_section_simple),
        test(get_section_with_multiple_sections),
        test(get_section_nonexisting),
        test(get_entry_simple),
        test(get_entry_nonexisting),

        test(get_str_value_simple),
        test(get_str_value_nonexisting),
        test(get_int_value_simple),
        test(get_int_value_nonexisting),
        test(get_int_value_invalid),
    };

    return execute_test_suite("cfg", tests, NULL, NULL);
}
