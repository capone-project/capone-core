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

#include "capone/crypto/asymmetric.h"

#include "test.h"

static struct cpn_encrypt_key_pair enc_pair;

static int setup()
{
    memset(&enc_pair, 0, sizeof(enc_pair));
    return 0;
}

static int teardown()
{
    return 0;
}

static void generate_encryption_key()
{
    assert_success(cpn_encrypt_key_pair_generate(&enc_pair));
}

static void encrypt_key_public_from_bin_succeeds()
{
    struct cpn_encrypt_key_public pk;

    assert_success(cpn_encrypt_key_pair_generate(&enc_pair));
    assert_success(cpn_encrypt_key_public_from_bin(&pk, enc_pair.pk.data, sizeof(enc_pair.pk)));
    assert_memory_equal(pk.data, enc_pair.pk.data, sizeof(pk.data));
}

static void encrypt_key_public_from_too_short_bin_fails()
{
    struct cpn_encrypt_key_public pk;

    assert_success(cpn_encrypt_key_pair_generate(&enc_pair));
    assert_failure(cpn_encrypt_key_public_from_bin(&pk, enc_pair.pk.data, sizeof(enc_pair.pk) - 1));
}

static void encrypt_key_public_from_too_long_bin_fails()
{
    struct cpn_encrypt_key_public pk;

    assert_success(cpn_encrypt_key_pair_generate(&enc_pair));
    assert_failure(cpn_encrypt_key_public_from_bin(&pk, enc_pair.pk.data, sizeof(enc_pair.pk) + 1));
}


int crypto_asymmetric_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(generate_encryption_key),

        test(encrypt_key_public_from_bin_succeeds),
        test(encrypt_key_public_from_too_short_bin_fails),
        test(encrypt_key_public_from_too_long_bin_fails),
    };

    return execute_test_suite("encrypt", tests, setup, teardown);
}
