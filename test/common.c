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

#include <sodium.h>

#include "lib/common.h"
#include "lib/keys.h"

#include "proto/test.pb-c.h"

#include "common.h"
#include "test.h"

static struct sd_keys keys;

static int setup()
{
    assert_success(sd_keys_from_config_file(&keys, "config/client.conf"));

    return 0;
}

static int teardown()
{
    return 0;
}

static void test_keys_from_existing_config_file()
{
    struct sd_keys keys;
    const char
        expected_sign_pk[] =
            "dcd8a532871434543784a79939d5979a"
            "539fae2cd2fc30ae1fe2b5814894be07",
        expected_sign_sk[] =
            "9109e235b1b133c5de0a0c4c5af746b4"
            "971e0f8a57e5f271cb52d74c502927d3"
            "dcd8a532871434543784a79939d5979a"
            "539fae2cd2fc30ae1fe2b5814894be07",
        expected_box_pk[] =
            "528f002cdc5c33cf0360416de0fdbfb4"
            "e76005841c6dcdf2a6f114a896f90825",
        expected_box_sk[] =
            "1870c4093d393fd60c9ae07b53d8b8ab"
            "faf2d2e8210f3f140c83dad74b4dd350";
    char actual_sign_pk[sizeof(expected_sign_pk)],
        actual_sign_sk[sizeof(expected_sign_sk)],
        actual_box_pk[sizeof(expected_box_pk)],
        actual_box_sk[sizeof(expected_box_sk)];

    assert_success(sd_keys_from_config_file(&keys, "config/client.conf"));

    sodium_bin2hex(actual_sign_pk, sizeof(actual_sign_pk),
            keys.pk.sign, sizeof(keys.pk.sign));
    sodium_bin2hex(actual_sign_sk, sizeof(actual_sign_sk),
            keys.sk.sign, sizeof(keys.sk.sign));
    sodium_bin2hex(actual_box_pk, sizeof(actual_box_pk),
            keys.pk.box, sizeof(keys.pk.box));
    sodium_bin2hex(actual_box_sk, sizeof(actual_box_sk),
            keys.sk.box, sizeof(keys.sk.box));

    assert_string_equal(expected_sign_pk, actual_sign_pk);
    assert_string_equal(expected_sign_sk, actual_sign_sk);
    assert_string_equal(expected_box_pk, actual_box_pk);
    assert_string_equal(expected_box_sk, actual_box_sk);
}

static void test_packing_signed_protobuf()
{
    uint8_t buf[] = "test-message";
    TestMessage msg = TEST_MESSAGE__INIT, *deserialized;
    Envelope *out = NULL;

    msg.value.data = buf;
    msg.value.len = sizeof(buf);

    assert_success(pack_signed_protobuf(&out, (ProtobufCMessage *) &msg, &keys));
    assert_non_null(out);

    assert_false(out->encrypted);
    assert_int_equal(out->pk.len, sizeof(keys.pk.sign));
    assert_memory_equal(out->pk.data, keys.pk.sign, sizeof(keys.pk.sign));

    assert_int_equal(out->mac.len, crypto_sign_BYTES);
    assert_success(crypto_sign_verify_detached(out->mac.data,
                out->data.data, out->data.len, keys.pk.sign));

    deserialized = test_message__unpack(NULL, out->data.len, out->data.data);
    assert_non_null(deserialized);
    assert_string_equal(deserialized->value.data, msg.value.data);

    envelope__free_unpacked(out, NULL);
    test_message__free_unpacked(deserialized, NULL);
}

static void test_unpacking_signed_protobuf()
{
    uint8_t buf[] = "test-message";
    TestMessage msg = TEST_MESSAGE__INIT,
                *unpacked;;
    Envelope *out = NULL;

    msg.value.data = buf;
    msg.value.len = sizeof(buf);

    assert_success(pack_signed_protobuf(&out, (ProtobufCMessage *) &msg, &keys));
    assert_non_null(out);

    assert_success(unpack_signed_protobuf(&test_message__descriptor,
                (ProtobufCMessage **) &unpacked, out));

    assert_string_equal(msg.value.data, unpacked->value.data);

    envelope__free_unpacked(out, NULL);
    test_message__free_unpacked(unpacked, NULL);
}

static void test_unpacking_falsely_signed_protobuf()
{
    uint8_t buf[] = "test-message";
    TestMessage msg = TEST_MESSAGE__INIT,
                *unpacked;
    Envelope *out = NULL;

    msg.value.data = buf;
    msg.value.len = sizeof(buf);

    assert_success(pack_signed_protobuf(&out, (ProtobufCMessage *) &msg, &keys));
    assert_non_null(out);
    randombytes(out->mac.data, out->mac.len);

    assert_failure(unpack_signed_protobuf(&test_message__descriptor,
                (ProtobufCMessage **) &unpacked, out));
    assert_null(unpacked);
}

int common_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_keys_from_existing_config_file),
        cmocka_unit_test(test_packing_signed_protobuf),
        cmocka_unit_test(test_unpacking_signed_protobuf),
        cmocka_unit_test(test_unpacking_falsely_signed_protobuf),
    };

    return execute_test_suite("cfg", tests, setup, teardown);
}
