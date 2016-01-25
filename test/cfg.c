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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <lib/cfg.h>
#include <lib/common.h>

#define assert_cfg_section(c, n, expected) do {                     \
        assert_string_equal((c).sections[(n)].name, (expected)); \
    } while (0)
#define assert_cfg_entry(c, section, n, expected_name, expected_value) do {                     \
        assert_string_equal((c).sections[(section)].entries[(n)].name, (expected_name));      \
        assert_string_equal((c).sections[(section)].entries[(n)].value, (expected_value));    \
    } while (0)

static struct cfg config;

static int setup()
{
    return 0;
}

static int teardown()
{
    cfg_free(&config);
    return 0;
}

static void parse_empty()
{
    const char text[] = "";

    assert_int_equal(cfg_parse_string(&config, text, sizeof(text)), 0);
    assert_int_equal(config.sections, 0);
}

static void parse_simple()
{
    const char text[] =
        "[one]\n"
        "two=three";

    assert_int_equal(cfg_parse_string(&config, text, sizeof(text)), 0);

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

    assert_int_equal(cfg_parse_string(&config, text, sizeof(text)), 0);

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

    assert_int_equal(cfg_parse_string(&config, text, sizeof(text)), 0);

    assert_int_equal(config.numsections, 2);

    assert_cfg_section(config, 0, "one");
    assert_cfg_section(config, 1, "two");

    assert_int_equal(config.sections[0].numentries, 0);
    assert_int_equal(config.sections[1].numentries, 0);
}

static void parse_leading_whitespace()
{
    const char text[] = " \n\t  \t[one]\n";

    assert_int_equal(cfg_parse_string(&config, text, sizeof(text)), 0);

    assert_int_equal(config.numsections, 1);
    assert_cfg_section(config, 0, "one");
}

static void parse_trailing_whitespace()
{
    const char text[] =
        "[one]\t   \t\n\t\n"
        "[two]";

    assert_int_equal(cfg_parse_string(&config, text, sizeof(text)), 0);

    assert_int_equal(config.numsections, 2);
    assert_cfg_section(config, 0, "one");
    assert_cfg_section(config, 1, "two");
}

static void parse_invalid_without_section()
{
    const char text[] =
        "one=two";

    assert_int_not_equal(cfg_parse_string(&config, text, sizeof(text)), 0);
    assert_int_equal(config.numsections, 0);
}

static void parse_invalid_section_format()
{
    const char text[] =
        "[bla";

    assert_int_not_equal(cfg_parse_string(&config, text, sizeof(text)), 0);
    assert_int_equal(config.numsections, 0);
}

static void parse_invalid_config_format()
{
    const char text[] =
        "[one]\n"
        "two three";

    assert_int_not_equal(cfg_parse_string(&config, text, sizeof(text)), 0);
    assert_int_equal(config.numsections, 0);
}

int cfg_test_run_suite()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(parse_empty),
        cmocka_unit_test(parse_simple),
        cmocka_unit_test(parse_empty_line),
        cmocka_unit_test(parse_multiple_sections),
        cmocka_unit_test(parse_leading_whitespace),
        cmocka_unit_test(parse_trailing_whitespace),
        cmocka_unit_test(parse_invalid_without_section),
        cmocka_unit_test(parse_invalid_section_format),
        cmocka_unit_test(parse_invalid_config_format),
    };

    return cmocka_run_group_tests_name("cfg", tests, setup, teardown);
}
