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

#include "capone/caps.h"
#include "capone/common.h"

#include "test.h"

#define NULL_SECRET "00000000000000000000000000000000" \
                    "00000000000000000000000000000000"
#define SECRET "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

static char *string;

static struct cpn_cap *root;
static struct cpn_cap *ref;
static struct cpn_sign_key_public pk;
static struct cpn_sign_key_public other_pk;

static int setup()
{
    root = NULL;
    ref = NULL;
    string = NULL;
    other_pk.data[0] = 1;
    return 0;
}

static int teardown()
{
    free(string);
    cpn_cap_free(root);
    cpn_cap_free(ref);
    return 0;
}

static void adding_capability_succeeds()
{
    assert_success(cpn_cap_create_root(&root));
}

static void adding_multiple_capabilities_succeeds()
{
    struct cpn_cap *caps[10];
    unsigned i;

    for (i = 0; i < ARRAY_SIZE(caps); i++)
        assert_success(cpn_cap_create_root(&caps[i]));
    for (i = 0; i < ARRAY_SIZE(caps) - 1; i++) {
        assert_memory_not_equal(&caps[i]->secret, &caps[i + 1]->secret, sizeof(caps[i]->secret));
        cpn_cap_free(caps[i]);
    }
}

static void creating_ref_succeeds()
{
    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, CPN_CAP_RIGHT_EXEC, &pk));
}

static void verifying_valid_ref_succeeds()
{
    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, CPN_CAP_RIGHT_EXEC, &pk));
    assert_success(cpn_caps_verify(ref, root, &pk, CPN_CAP_RIGHT_EXEC));
}

static void verifying_valid_ref_with_different_pk_fails()
{
    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, CPN_CAP_RIGHT_EXEC, &pk));
    assert_failure(cpn_caps_verify(ref, root, &other_pk, CPN_CAP_RIGHT_EXEC));
}

static void verifying_valid_ref_with_different_rights_fails()
{
    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, CPN_CAP_RIGHT_EXEC, &pk));
    assert_failure(cpn_caps_verify(ref, root, &pk, CPN_CAP_RIGHT_TERM));
}

static void verifying_valid_ref_with_additional_rights_fails()
{
    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, CPN_CAP_RIGHT_EXEC, &pk));
    assert_failure(cpn_caps_verify(ref, root, &pk, CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM));
}

static void parsing_cap_succeeds()
{
    char secret[] = SECRET ":x";

    assert_success(cpn_cap_from_string(&ref, secret));
    assert_int_equal(ref->rights, CPN_CAP_RIGHT_EXEC);
}

static void parsing_cap_with_multiple_rights_succeeds()
{
    char secret[] = SECRET ":xt";

    assert_success(cpn_cap_from_string(&ref, secret));
    assert_int_equal(ref->rights, CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM);
}

static void parsing_cap_with_invalid_secret_length_fails()
{
    char secret[] = SECRET "a:x";

    assert_failure(cpn_cap_from_string(&ref, secret));
}

static void parsing_cap_with_invalid_secret_chars_fails()
{
    char secret[] = SECRET ":x";
    secret[0] = 'x';

    assert_failure(cpn_cap_from_string(&ref, secret));
}

static void parsing_cap_with_invalid_rights_fails()
{
    char secret[] = SECRET ":z";

    assert_failure(cpn_cap_from_string(&ref, secret));
}

static void parsing_cap_with_no_rights_fails()
{
    char secret[] = SECRET ":";

    assert_failure(cpn_cap_from_string(&ref, secret));
}

static void cap_to_string_succeeds_with_single_right()
{
    struct cpn_cap cap;

    memset(&cap, 0, sizeof(struct cpn_cap));
    cap.rights = CPN_CAP_RIGHT_EXEC;

    assert_success(cpn_cap_to_string(&string, &cap));
    assert_string_equal(string, NULL_SECRET ":x");
}

static void cap_to_string_succeeds_with_multiple_rights()
{
    struct cpn_cap cap;

    memset(&cap, 0, sizeof(struct cpn_cap));
    cap.rights = CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM;

    assert_success(cpn_cap_to_string(&string, &cap));
    assert_string_equal(string, NULL_SECRET ":xt");
}

static void cap_to_string_fails_without_rights()
{
    struct cpn_cap cap;

    memset(&cap, 0, sizeof(struct cpn_cap));

    assert_failure(cpn_cap_to_string(&string, &cap));
}

int caps_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(adding_capability_succeeds),
        test(adding_multiple_capabilities_succeeds),

        test(creating_ref_succeeds),

        test(verifying_valid_ref_succeeds),
        test(verifying_valid_ref_with_different_pk_fails),
        test(verifying_valid_ref_with_different_rights_fails),
        test(verifying_valid_ref_with_additional_rights_fails),

        test(parsing_cap_succeeds),
        test(parsing_cap_with_multiple_rights_succeeds),
        test(parsing_cap_with_invalid_secret_length_fails),
        test(parsing_cap_with_invalid_secret_chars_fails),
        test(parsing_cap_with_invalid_rights_fails),
        test(parsing_cap_with_no_rights_fails),

        test(cap_to_string_succeeds_with_single_right),
        test(cap_to_string_succeeds_with_multiple_rights),
        test(cap_to_string_fails_without_rights)
    };

    return execute_test_suite("caps", tests, NULL, NULL);
}
