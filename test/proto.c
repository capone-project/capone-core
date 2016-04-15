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

#include "lib/channel.h"
#include "lib/common.h"
#include "lib/proto.h"

#include "test.h"

extern void stub_sockets(struct sd_channel *local, struct sd_channel *remote);

struct await_encryption_args {
    struct sd_channel *c;
    struct sd_sign_key_pair *k;
};

static struct sd_channel local, remote;
static struct sd_sign_key_pair local_keys, remote_keys;

static int setup()
{
    memset(&local, 0, sizeof(local));
    memset(&remote, 0, sizeof(remote));

    stub_sockets(&local, &remote);
    local.type = remote.type = SD_CHANNEL_TYPE_TCP;
    local.crypto = remote.crypto = SD_CHANNEL_CRYPTO_NONE;

    return 0;
}

static int teardown()
{
    sd_channel_close(&local);
    sd_channel_close(&remote);
    return 0;
}

static void *await_encryption(void *payload)
{
    struct await_encryption_args *args = (struct await_encryption_args *) payload;
    struct sd_sign_key_public remote_key;

    assert_success(sd_proto_await_encryption(args->c, args->k, &remote_key));
    assert_memory_equal(&remote_key, &local_keys.pk, sizeof(remote_key));
    assert(args->c->crypto == SD_CHANNEL_CRYPTO_SYMMETRIC);

    return NULL;
}

static void encryption_initiation_succeeds()
{
    struct sd_thread t;
    struct await_encryption_args args = {
        &remote, &remote_keys
    };

    sd_spawn(&t, await_encryption, &args);
    assert_success(sd_proto_initiate_encryption(&local,
                &local_keys, &remote_keys.pk));
    sd_join(&t, NULL);

    assert(local.crypto == SD_CHANNEL_CRYPTO_SYMMETRIC);
    assert_memory_equal(&local.key, &remote.key, sizeof(local.key));
    assert_memory_equal(local.local_nonce, remote.remote_nonce, sizeof(local.local_nonce));
    assert_memory_equal(local.remote_nonce, remote.local_nonce, sizeof(local.local_nonce));
}

int proto_test_run_suite(void)
{
    const struct CMUnitTest tests[] = {
        test(encryption_initiation_succeeds)
    };

    assert_success(sd_sign_key_pair_generate(&local_keys));
    assert_success(sd_sign_key_pair_generate(&remote_keys));

    return execute_test_suite("proto", tests, setup, teardown);
}
