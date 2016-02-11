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
#include <stdio.h>
#include <sodium.h>

#include "lib/channel.h"
#include "lib/common.h"

int main(int argc, char *argv[])
{
    const char *config, *key, *host, *port;
    struct sd_channel channel;
    struct sd_keys keys;
    struct sd_keys_public remote_keys;
    uint8_t local_nonce[crypto_box_NONCEBYTES],
        remote_nonce[crypto_box_NONCEBYTES];

    if (argc != 5) {
        printf("USAGE: %s <CONFIG> <KEY> <HOST> <PORT>\n", argv[0]);
        return -1;
    }

    config = argv[1];
    key = argv[2];
    host = argv[3];
    port = argv[4];

    if (sodium_init() < 0) {
        puts("Could not init libsodium");
        return -1;
    }

    if (sd_keys_from_config_file(&keys, config) < 0) {
        puts("Could not parse config");
        return -1;
    }

    if (sd_keys_public_from_hex(&remote_keys, key) < 0) {
        puts("Could not parse remote public key");
        return -1;
    }

    randombytes_buf(local_nonce, sizeof(local_nonce));
    memcpy(remote_nonce, local_nonce, sizeof(remote_nonce));
    sodium_increment(remote_nonce, sizeof(remote_nonce));

    if (sd_channel_init_from_host(&channel, host, port, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Could not initialize channel");
        return -1;
    }

    if (sd_channel_set_crypto_encrypt(&channel, &keys, &remote_keys,
            local_nonce, remote_nonce) < 0) {
        puts("Could not enable encryption");
        return -1;
    }

    if (sd_channel_connect(&channel) < 0) {
        puts("Could not connect to server");
        return -1;
    }

    sd_channel_close(&channel);

    return 0;
}
