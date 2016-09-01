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
#include <stdlib.h>
#include <setjmp.h>
#include <stdio.h>

#ifndef inline
#define inline __inline__
#include <cmocka.h>
#undef inline
#endif

#include "capone/channel.h"

#define assert_success(fn) assert_int_equal((fn), 0)
#define assert_failure(fn) assert_int_equal((fn), -1)

void assert_file_equal(FILE *f, const char *expected);

# define execute_test_suite(group_name, group_tests, group_setup, group_teardown) \
        _execute_test_suite(group_name, group_tests, sizeof(group_tests) / sizeof(group_tests)[0], group_setup, group_teardown)
int _execute_test_suite(const char *name, const struct CMUnitTest *tests, const size_t count,
        CMFixtureFunction setup, CMFixtureFunction teardown);

#define test(f) cmocka_unit_test_setup_teardown((f), setup, teardown)

void stub_sockets(struct cpn_channel *local, struct cpn_channel *remote, enum cpn_channel_type type);
