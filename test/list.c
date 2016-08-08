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


#include "capone/list.h"

#include "test.h"

static struct cpn_list list;
static int data[] = { 0, 1, 2, 3 };

static int setup()
{
    cpn_list_clear(&list);
    return 0;
}

static int teardown()
{
    return 0;
}

static void list_initialization_succeeds()
{
    assert_success(cpn_list_init(&list));
    assert_null(list.head);
    assert_null(list.tail);
}

static void appending_single_element_succeeds()
{
    cpn_list_append(&list, &data[0]);

    assert_null(list.head->next);
    assert_null(list.head->prev);

    assert_int_equal(* (int *) list.head->data, data[0]);
    assert_int_equal(* (int *) list.tail->data, data[0]);
}

static void appending_multiple_elements_succeeds()
{
    int i ;

    for (i = 0; i < 4; i++)
        assert_success(cpn_list_append(&list, &data[i]));
    for (i = 0; i < 4; i++)
        assert_ptr_equal(cpn_list_get(&list, i)->data, &data[i]);
}

static void appending_same_element_multiple_times_succeeds()
{
    int i ;

    for (i = 0; i < 4; i++)
        assert_success(cpn_list_append(&list, &data[0]));
    for (i = 0; i < 4; i++)
        assert_ptr_equal(cpn_list_get(&list, i)->data, &data[0]);
}

static void removing_single_entry_succeeds()
{
    assert_success(cpn_list_append(&list, &data[0]));
    assert_success(cpn_list_remove(&list, list.head));

    assert_null(list.head);
    assert_null(list.tail);
}

static void removing_head_succeeds()
{
    assert_success(cpn_list_append(&list, &data[0]));
    assert_success(cpn_list_append(&list, &data[1]));

    assert_success(cpn_list_remove(&list, list.head));

    assert_ptr_equal(list.head->data, &data[1]);
    assert_ptr_equal(list.tail->data, &data[1]);
}

static void removing_tail_succeeds()
{
    assert_success(cpn_list_append(&list, &data[0]));
    assert_success(cpn_list_append(&list, &data[1]));

    assert_success(cpn_list_remove(&list, list.tail));

    assert_ptr_equal(list.head->data, &data[0]);
    assert_ptr_equal(list.tail->data, &data[0]);
}

static void removing_in_between_succeeds()
{
    assert_success(cpn_list_append(&list, &data[0]));
    assert_success(cpn_list_append(&list, &data[1]));
    assert_success(cpn_list_append(&list, &data[2]));

    assert_success(cpn_list_remove(&list, list.head->next));

    assert_ptr_equal(list.head->data, &data[0]);
    assert_ptr_equal(list.tail->data, &data[2]);

    assert_ptr_equal(list.head->next, list.tail);
    assert_ptr_equal(list.tail->prev, list.head);
}

static void removing_null_fails()
{
    assert_failure(cpn_list_remove(&list, NULL));
}

static void removing_nonexistent_fails()
{
    struct cpn_list_entry e;

    assert_failure(cpn_list_remove(&list, &e));
}

static void foreach_entry_with_empty_list_succeeds()
{
    struct cpn_list_entry *it;
    int called = 0;

    cpn_list_foreach_entry(&list, it)
        called = 1;
    assert_false(called);
}

static void foreach_entry_with_single_element_succeeds()
{
    struct cpn_list_entry *it;
    int called = 0;

    assert_success(cpn_list_append(&list, &data[0]));

    cpn_list_foreach_entry(&list, it)
        called++;
    assert_int_equal(called, 1);
}

static void foreach_entry_with_many_elements_succeeds()
{
    struct cpn_list_entry *it;
    int i, sum = 0, called = 0;

    for (i = 0; i < 50; i++) {
        sum += data[i % 4];
        assert_success(cpn_list_append(&list, &data[i % 4]));
    }

    cpn_list_foreach_entry(&list, it) {
        sum -= *(int *) it->data;
        called++;
    }

    assert_int_equal(called, 50);
    assert_int_equal(sum, 0);
}

static void foreach_with_empty_list_succeeds()
{
    struct cpn_list_entry *it;
    int *ptr = NULL;
    int called = 0;

    cpn_list_foreach(&list, it, ptr)
        called = 1;
    assert_false(called);
    assert_null(ptr);
}

static void foreach_with_single_entry_succeeds()
{
    struct cpn_list_entry *it;
    int *ptr;
    int called = 0;

    assert_success(cpn_list_append(&list, &data[0]));

    cpn_list_foreach(&list, it, ptr) {
        assert_ptr_equal(ptr, &data[0]);
        called++;
    }
    assert_int_equal(called, 1);
}

static void foreach_with_multiple_entries_succeeds()
{
    struct cpn_list_entry *it;
    int *ptr;
    int called = 0;

    assert_success(cpn_list_append(&list, &data[0]));
    assert_success(cpn_list_append(&list, &data[1]));
    assert_success(cpn_list_append(&list, &data[2]));
    assert_success(cpn_list_append(&list, &data[3]));

    cpn_list_foreach(&list, it, ptr) {
        assert_ptr_equal(ptr, &data[called]);
        called++;
    }
    assert_int_equal(called, 4);
}

static void count_succeeds_with_empty_list()
{
    assert_int_equal(cpn_list_count(&list), 0);
}

static void count_succeeds_with_one_entry()
{
    cpn_list_append(&list, &data[0]);
    assert_int_equal(cpn_list_count(&list), 1);
}

static void count_succeeds_with_multiple_entries()
{
    cpn_list_append(&list, &data[0]);
    cpn_list_append(&list, &data[1]);
    cpn_list_append(&list, &data[2]);
    cpn_list_append(&list, &data[3]);

    assert_int_equal(cpn_list_count(&list), 4);
}

int list_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(list_initialization_succeeds),
        test(appending_single_element_succeeds),
        test(appending_multiple_elements_succeeds),
        test(appending_same_element_multiple_times_succeeds),

        test(removing_single_entry_succeeds),
        test(removing_head_succeeds),
        test(removing_tail_succeeds),
        test(removing_in_between_succeeds),
        test(removing_null_fails),
        test(removing_nonexistent_fails),

        test(foreach_entry_with_empty_list_succeeds),
        test(foreach_entry_with_single_element_succeeds),
        test(foreach_entry_with_many_elements_succeeds),

        test(foreach_with_empty_list_succeeds),
        test(foreach_with_single_entry_succeeds),
        test(foreach_with_multiple_entries_succeeds),

        test(count_succeeds_with_empty_list),
        test(count_succeeds_with_one_entry),
        test(count_succeeds_with_multiple_entries)
    };

    return execute_test_suite("list", tests, NULL, NULL);
}
