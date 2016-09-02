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

#define SYMMETRIC_KEY "da20c55a1735c691205334472cb8cb30905598e1f600aada2c1879e1fdc22502"
#define NULL_SECRET "00000000000000000000000000000000" \
                    "00000000000000000000000000000000"
#define SECRET "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define PK "284689fdc4aa73564d957db540ea55e1d0fc2e2e7cde14b25a5886a492b54f6d"
#define SK "edef59e86825d398a58b23e68f0a654f32851ccdd1c72e6522e3c8247c15177c" \
           "284689fdc4aa73564d957db540ea55e1d0fc2e2e7cde14b25a5886a492b54f6d"
#define OTHER_PK "0e29d67c6f96d2594bd7af24dc2ab3bc" \
                 "3eebb1f8444b422e30441b0743d5dde3"
#define CFG "[core]\npublic_key="PK"\nsecret_key="SK"\n"

void assert_file_equal(FILE *f, const char *expected);

# define execute_test_suite(group_name, group_tests, group_setup, group_teardown) \
        _execute_test_suite(group_name, group_tests, sizeof(group_tests) / sizeof(group_tests)[0], group_setup, group_teardown)
int _execute_test_suite(const char *name, const struct CMUnitTest *tests, const size_t count,
        CMFixtureFunction setup, CMFixtureFunction teardown);

#define test(f) cmocka_unit_test_setup_teardown((f), setup, teardown)

void stub_sockets(struct cpn_channel *local, struct cpn_channel *remote, enum cpn_channel_type type);
