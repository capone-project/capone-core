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

#include "capone/acl.h"

#include "test.h"

static struct cpn_acl acl;
static struct cpn_sign_pk key1, key2;

static int setup()
{
    memset(&acl, 0, sizeof(acl));
    return 0;
}

static int teardown()
{
    cpn_acl_clear(&acl);
    return 0;
}

static void adding_entry_works()
{
    assert_success(cpn_acl_add_right(&acl,&key1, CPN_ACL_RIGHT_EXEC));
}

static void adding_entry_twice_fails()
{
    assert_success(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_failure(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
}

static void adding_entry_with_different_rights_works()
{
    assert_success(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_success(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_TERMINATE));
}

static void adding_entry_with_different_keys_works()
{
    assert_success(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_success(cpn_acl_add_right(&acl, &key2, CPN_ACL_RIGHT_EXEC));
}

static void adding_entry_allows()
{
    assert_success(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_true(cpn_acl_is_allowed(&acl, &key1, CPN_ACL_RIGHT_EXEC));
}

static void adding_entry_does_not_allow_other_rights()
{
    assert_success(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_true(cpn_acl_is_allowed(&acl, &key1, CPN_ACL_RIGHT_EXEC));
}

static void adding_wildcard_allows_right_for_everybody()
{
    assert_success(cpn_acl_add_wildcard(&acl, CPN_ACL_RIGHT_EXEC));
    assert_true(cpn_acl_is_allowed(&acl, &key1, CPN_ACL_RIGHT_EXEC));
}

static void adding_wildcard_allows_only_specific_right()
{
    assert_success(cpn_acl_add_wildcard(&acl, CPN_ACL_RIGHT_EXEC));
    assert_false(cpn_acl_is_allowed(&acl, &key1, CPN_ACL_RIGHT_TERMINATE));
}

static void removing_nonexistent_entry_fails()
{
    assert_failure(cpn_acl_remove_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
}

static void removing_entry_removes_right()
{
    assert_success(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_success(cpn_acl_remove_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_false(cpn_acl_is_allowed(&acl, &key1, CPN_ACL_RIGHT_EXEC));
}

static void removing_entry_does_not_remove_other_rights()
{
    assert_success(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_success(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_TERMINATE));
    assert_success(cpn_acl_remove_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_true(cpn_acl_is_allowed(&acl, &key1, CPN_ACL_RIGHT_TERMINATE));
}

static void removing_entry_does_not_remove_other_keys()
{
    assert_success(cpn_acl_add_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_success(cpn_acl_add_right(&acl, &key2, CPN_ACL_RIGHT_EXEC));
    assert_success(cpn_acl_remove_right(&acl, &key1, CPN_ACL_RIGHT_EXEC));
    assert_true(cpn_acl_is_allowed(&acl, &key2, CPN_ACL_RIGHT_EXEC));
}

static void empty_acl_allows_nothing()
{
    assert_success(cpn_acl_is_allowed(&acl, &key1, CPN_ACL_RIGHT_TERMINATE));
}

int acl_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(adding_entry_works),
        test(adding_entry_twice_fails),
        test(adding_entry_with_different_rights_works),
        test(adding_entry_with_different_keys_works),
        test(adding_entry_allows),
        test(adding_entry_does_not_allow_other_rights),
        test(adding_wildcard_allows_right_for_everybody),
        test(adding_wildcard_allows_only_specific_right),
        test(removing_nonexistent_entry_fails),
        test(removing_entry_removes_right),
        test(removing_entry_does_not_remove_other_rights),
        test(removing_entry_does_not_remove_other_keys),
        test(empty_acl_allows_nothing),
    };

    key1.data[0] = 1;
    key2.data[0] = 2;

    return execute_test_suite("acl", tests, NULL, NULL);
}
