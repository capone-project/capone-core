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

static int setup()
{
    return 0;
}

static int teardown()
{
    return 0;
}

static void parse_simple()
{
    const char text[] =
        "[one]\n"
        "two=three";
    struct cfg c;

    assert_int_equal(cfg_parse_string(&c, text, sizeof(text)), 0);

    assert_int_equal(c.numsections, 1);
    assert_string_equal(c.sections[0].name, "one");

    assert_int_equal(c.sections[0].numentries, 1);
    assert_string_equal(c.sections[0].entries[0].name, "two");
    assert_string_equal(c.sections[0].entries[0].value, "three");
}

static void parse_multiple_sections()
{
    const char text[] =
        "[one]\n"
        "[two]";
    struct cfg c;

    assert_int_equal(cfg_parse_string(&c, text, sizeof(text)), 0);

    assert_int_equal(c.numsections, 2);

    assert_string_equal(c.sections[0].name, "one");
    assert_int_equal(c.sections[0].numentries, 0);

    assert_string_equal(c.sections[1].name, "two");
    assert_int_equal(c.sections[1].numentries, 0);
}

int cfg_test_run_suite()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(parse_simple),
        cmocka_unit_test(parse_multiple_sections),
    };

    return cmocka_run_group_tests_name("cfg", tests, setup, teardown);
}
