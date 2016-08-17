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

void assert_file_equal(FILE *f, const char *expected)
{
    long size;
    char *data;

    assert_success(fseek(f, 0, SEEK_END));
    size = ftell(f);
    assert_success(fseek(f, 0, SEEK_SET));

    data = malloc(size + 1);
    assert_int_equal(fread(data, size, 1, f), 1);
    data[size] = 0;

    assert_success(fclose(f));

    assert_string_equal(data, expected);

    free(data);
}

int _execute_test_suite(const char *name, const struct CMUnitTest *tests, const size_t count,
        CMFixtureFunction setup, CMFixtureFunction teardown)
{
    printf("[==========] Running testsuite %s\n", name);
    return _cmocka_run_group_tests(name, tests, count, setup, teardown);
}
