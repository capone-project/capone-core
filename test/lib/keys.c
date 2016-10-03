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

#include "capone/cfg.h"
#include "capone/keys.h"
#include "capone/common.h"

#include "test.h"

static struct cpn_encrypt_key_pair enc_pair;

static struct cpn_symmetric_key key;
static struct cpn_symmetric_key_hex key_hex;

static void assert_symmetric_key_matches(const struct cpn_symmetric_key *key, const char *str)
{
    uint8_t bin[sizeof(key->data)];
    assert_success(parse_hex(bin, sizeof(bin), str, strlen(str)));
    assert_memory_equal(bin, key->data, sizeof(key->data));
}

static int setup()
{
    memset(&enc_pair, 0, sizeof(enc_pair));
    memset(&key, 0, sizeof(key));
    return 0;
}

static int teardown()
{
    return 0;
}

static void generate_symmetric_key()
{
    assert_success(cpn_symmetric_key_generate(&key));
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

static void symmetric_key_from_hex_succeeds()
{
    assert_success(cpn_symmetric_key_from_hex(&key, SYMMETRIC_KEY));
    assert_symmetric_key_matches(&key, SYMMETRIC_KEY);
}

static void symmetric_key_from_too_short_hex_fails()
{
    assert_failure(cpn_symmetric_key_from_hex(&key, "abc1234"));
}

static void symmetric_key_from_too_long_hex_fails()
{
    assert_failure(cpn_symmetric_key_from_hex(&key, SYMMETRIC_KEY "1"));
}

static void symmetric_key_from_bin_succeeds()
{
    struct cpn_symmetric_key bin;

    assert_success(cpn_symmetric_key_from_hex(&bin, SYMMETRIC_KEY));
    assert_success(cpn_symmetric_key_from_bin(&key, bin.data, sizeof(bin.data)));
    assert_memory_equal(&bin, &key, sizeof(bin));
}

static void symmetric_key_from_too_short_bin_fails()
{
    struct cpn_symmetric_key bin;

    assert_success(cpn_symmetric_key_from_hex(&bin, SYMMETRIC_KEY));
    assert_failure(cpn_symmetric_key_from_bin(&key, bin.data, sizeof(bin.data) - 1));
}

static void symmetric_key_from_too_long_bin_fails()
{
    assert_success(cpn_symmetric_key_from_hex(&key, SYMMETRIC_KEY));
    assert_failure(cpn_symmetric_key_from_bin(&key, key.data, sizeof(key.data) + 1));
}

static void symmetric_key_hex_from_bin_succeeds()
{
    assert_success(cpn_symmetric_key_from_hex(&key, SYMMETRIC_KEY));
    assert_success(cpn_symmetric_key_hex_from_bin(&key_hex, key.data, sizeof(key.data)));
    assert_string_equal(key_hex.data, SYMMETRIC_KEY);
}

static void symmetric_key_hex_from_too_short_bin_fails()
{
    assert_success(cpn_symmetric_key_from_hex(&key, SYMMETRIC_KEY));
    assert_failure(cpn_symmetric_key_hex_from_bin(&key_hex, key.data, sizeof(key.data) - 1));
}

static void symmetric_key_hex_from_too_long_bin_fails()
{
    assert_success(cpn_symmetric_key_from_hex(&key, SYMMETRIC_KEY));
    assert_failure(cpn_symmetric_key_hex_from_bin(&key_hex, key.data, sizeof(key.data) + 1));
}

static void symmetric_key_hex_from_key_succeeds()
{
    assert_success(cpn_symmetric_key_from_hex(&key, SYMMETRIC_KEY));
    cpn_symmetric_key_hex_from_key(&key_hex, &key);
    assert_string_equal(key_hex.data, SYMMETRIC_KEY);
}

int keys_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(generate_symmetric_key),
        test(generate_encryption_key),

        test(encrypt_key_public_from_bin_succeeds),
        test(encrypt_key_public_from_too_short_bin_fails),
        test(encrypt_key_public_from_too_long_bin_fails),

        test(symmetric_key_from_hex_succeeds),
        test(symmetric_key_from_too_short_hex_fails),
        test(symmetric_key_from_too_long_hex_fails),
        test(symmetric_key_from_bin_succeeds),
        test(symmetric_key_from_too_short_bin_fails),
        test(symmetric_key_from_too_long_bin_fails),
        test(symmetric_key_hex_from_bin_succeeds),
        test(symmetric_key_hex_from_too_short_bin_fails),
        test(symmetric_key_hex_from_too_long_bin_fails),
        test(symmetric_key_hex_from_key_succeeds)
    };

    return execute_test_suite("keys", tests, setup, teardown);
}
