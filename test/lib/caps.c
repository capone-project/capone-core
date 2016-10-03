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

static char *string;

static struct cpn_cap *root;
static struct cpn_cap *ref;
static struct cpn_sign_pk pk;
static struct cpn_sign_pk other_pk;

static int setup()
{
    root = NULL;
    ref = NULL;
    string = NULL;
    assert_success(cpn_sign_pk_from_hex(&pk, PK));
    assert_success(cpn_sign_pk_from_hex(&other_pk, OTHER_PK));
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
    assert_int_equal(root->chain_depth, 0);
    assert_null(root->chain);
}

static void creating_ref_succeeds()
{
    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, CPN_CAP_RIGHT_EXEC, &pk));

    assert_int_equal(ref->chain_depth, 1);
    assert_int_equal(ref->chain[0].rights, CPN_CAP_RIGHT_EXEC);
    assert_memory_equal(&ref->chain[0].identity, &pk, sizeof(pk));
}

static void creating_nested_refs_succeeds()
{
    struct cpn_cap *nested;

    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, CPN_CAP_RIGHT_EXEC, &pk));
    assert_success(cpn_cap_create_ref(&nested, ref, CPN_CAP_RIGHT_EXEC, &other_pk));

    assert_int_equal(nested->chain_depth, 2);
    assert_int_equal(nested->chain[0].rights, CPN_CAP_RIGHT_EXEC);
    assert_memory_equal(&nested->chain[0].identity, &pk, sizeof(pk));
    assert_int_equal(nested->chain[1].rights, CPN_CAP_RIGHT_EXEC);
    assert_memory_equal(&nested->chain[1].identity, &other_pk, sizeof(other_pk));

    cpn_cap_free(nested);
}

static void creating_nested_refs_with_additional_rights_fails()
{
    struct cpn_cap *nested;

    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, CPN_CAP_RIGHT_EXEC, &pk));
    assert_failure(cpn_cap_create_ref(&nested, ref, CPN_CAP_RIGHT_EXEC|CPN_CAP_RIGHT_TERM, &other_pk));
    assert_null(nested);
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

static void verifying_reference_extending_rights_fails()
{
    struct cpn_cap *other;

    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, CPN_CAP_RIGHT_EXEC, &pk));
    assert_success(cpn_cap_create_ref(&other, root, CPN_CAP_RIGHT_EXEC, &pk));

    other->chain[0].rights |= CPN_CAP_RIGHT_TERM;
    other->chain[1].rights |= CPN_CAP_RIGHT_TERM;

    assert_failure(cpn_caps_verify(other, root, &pk, CPN_CAP_RIGHT_TERM));

    cpn_cap_free(other);
}

static void parsing_cap_succeeds()
{
    char secret[] = SECRET;

    assert_success(cpn_cap_from_string(&ref, secret));
}

static void parsing_cap_with_invalid_secret_length_fails()
{
    char secret[] = SECRET "a";

    assert_failure(cpn_cap_from_string(&ref, secret));
}

static void parsing_cap_with_invalid_secret_chars_fails()
{
    char secret[] = SECRET;
    secret[0] = 'x';

    assert_failure(cpn_cap_from_string(&ref, secret));
}

static void parsing_root_cap_with_rights_fails()
{
    char secret[] = SECRET ":r";

    assert_failure(cpn_cap_from_string(&ref, secret));
}

static void parsing_cap_with_single_chain_succeeds()
{
    char secret[] = SECRET "|" PK ":t";
    assert_success(cpn_cap_from_string(&ref, secret));

    assert_int_equal(ref->chain_depth, 1);
    assert_int_equal(ref->chain[0].rights, CPN_CAP_RIGHT_TERM);
    assert_memory_equal(&ref->chain[0].identity, &pk, sizeof(pk));
}

static void parsing_cap_with_multiple_chain_elements_succeeds()
{
    char secret[] = SECRET "|" PK ":t|" OTHER_PK ":t";
    assert_success(cpn_cap_from_string(&ref, secret));

    assert_int_equal(ref->chain_depth, 2);
    assert_memory_equal(&ref->chain[0].identity, &pk, sizeof(pk));
    assert_int_equal(ref->chain[0].rights, CPN_CAP_RIGHT_TERM);
    assert_memory_equal(&ref->chain[1].identity, &other_pk, sizeof(other_pk));
    assert_int_equal(ref->chain[1].rights, CPN_CAP_RIGHT_TERM);
}

static void parsing_cap_with_extending_rights_fails()
{
    char secret[] = SECRET "|" PK ":t|" PK ":xt";
    assert_failure(cpn_cap_from_string(&ref, secret));
}

static void parsing_cap_with_invalid_right_fails()
{
    char secret[] = SECRET "|" PK ":z";
    assert_failure(cpn_cap_from_string(&ref, secret));
}

static void cap_to_string_succeeds_with_root_ref()
{
    struct cpn_cap cap;

    memset(&cap, 0, sizeof(struct cpn_cap));

    assert_success(cpn_cap_to_string(&string, &cap));
    assert_string_equal(string, NULL_SECRET);
}

static void cap_to_string_succeeds_with_reference()
{
    struct cpn_cap cap;

    memset(&cap, 0, sizeof(struct cpn_cap));

    assert_success(cpn_cap_create_ref(&ref, &cap, CPN_CAP_RIGHT_EXEC | CPN_CAP_RIGHT_TERM, &pk));

    assert_success(cpn_cap_to_string(&string, ref));

    assert_string_equal(string, "c9e6e247596f2dce001d6b60ff6c75a6"
                                "84d75047ab0c78731f9bdf30ff861fe8"
                                "|" PK ":xt");
}

static void reference_to_string_fails_without_rights()
{
    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, 0, &pk));

    assert_failure(cpn_cap_to_string(&string, ref));
}

static void dup_of_root_cap_succeeds()
{
    struct cpn_cap *dup;

    assert_success(cpn_cap_create_root(&root));
    dup = cpn_cap_dup(root);

    assert_non_null(dup);
    assert_memory_equal(dup->secret, root->secret, sizeof(dup->secret));
    assert_int_equal(dup->chain_depth, 0);
    assert_null(dup->chain);

    cpn_cap_free(dup);
}

static void dup_of_reference_cap_succeeds()
{
    struct cpn_cap *dup;

    assert_success(cpn_cap_create_root(&root));
    assert_success(cpn_cap_create_ref(&ref, root, 0, &pk));

    dup = cpn_cap_dup(ref);

    assert_non_null(dup);
    assert_int_equal(dup->chain_depth, 1);
    assert_memory_equal(dup->chain, ref->chain, sizeof(*dup->chain) * dup->chain_depth);

    cpn_cap_free(dup);
}

int caps_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(adding_capability_succeeds),

        test(creating_ref_succeeds),
        test(creating_nested_refs_succeeds),
        test(creating_nested_refs_with_additional_rights_fails),

        test(verifying_valid_ref_succeeds),
        test(verifying_valid_ref_with_different_pk_fails),
        test(verifying_valid_ref_with_different_rights_fails),
        test(verifying_valid_ref_with_additional_rights_fails),
        test(verifying_reference_extending_rights_fails),

        test(parsing_cap_succeeds),
        test(parsing_cap_with_invalid_secret_length_fails),
        test(parsing_cap_with_invalid_secret_chars_fails),
        test(parsing_root_cap_with_rights_fails),
        test(parsing_cap_with_single_chain_succeeds),
        test(parsing_cap_with_multiple_chain_elements_succeeds),
        test(parsing_cap_with_extending_rights_fails),
        test(parsing_cap_with_invalid_right_fails),

        test(cap_to_string_succeeds_with_root_ref),
        test(cap_to_string_succeeds_with_reference),
        test(reference_to_string_fails_without_rights),

        test(dup_of_root_cap_succeeds),
        test(dup_of_reference_cap_succeeds)
    };

    return execute_test_suite("caps", tests, NULL, NULL);
}
