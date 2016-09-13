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

#include "capone/global.h"

#include "test.h"

static int called = 0;

static int setup()
{
    return 0;
}

static int teardown()
{
    return 0;
}

static void init_shutdown_succeeds()
{
    assert_success(cpn_global_init());
}

static int shutdown_cb(void)
{
    called++;
    return 0;
}

static void registering_callback_succeeds()
{
    assert_success(cpn_global_on_shutdown(shutdown_cb));
    assert_success(cpn_global_shutdown());
    assert_int_equal(called, 1);
}

int global_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(init_shutdown_succeeds),
        test(registering_callback_succeeds)
    };

    return execute_test_suite("global", tests, setup, teardown);
}
