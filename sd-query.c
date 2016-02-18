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

#include "proto/encryption.pb-c.h"
#include "proto/query.pb-c.h"

#include "lib/channel.h"
#include "lib/common.h"

static struct sd_keys keys;
static struct sd_keys_public remote_keys;

static int negotiate_encryption(struct sd_channel *channel)
{
    uint8_t nonce[crypto_box_NONCEBYTES];
    EncryptionNegotiationMessage *response,
        negotiation = ENCRYPTION_NEGOTIATION_MESSAGE__INIT;
    Envelope *env;

    /* TODO: use correct nonce */
    randombytes_buf(nonce, sizeof(nonce));
    negotiation.nonce.data = nonce;
    negotiation.nonce.len = sizeof(nonce);

    if (pack_signed_protobuf(&env, (ProtobufCMessage *) &negotiation,
                &keys, &remote_keys) < 0) {
        puts("Could not pack negotiation");
        return -1;
    }
    if (sd_channel_write_protobuf(channel, (ProtobufCMessage *) env) < 0) {
        puts("Could not send negotiation");
        return -1;
    }
    envelope__free_unpacked(env, NULL);

    if (sd_channel_receive_protobuf(channel, &envelope__descriptor,
            (ProtobufCMessage **) &env) < 0) {
        puts("Failed receiving negotiation response");
        return -1;
    }
    if (unpack_signed_protobuf(&encryption_negotiation_message__descriptor,
                (ProtobufCMessage **) &response, env, &keys) < 0) {
        puts("Failed unpacking protobuf");
        return -1;
    }
    envelope__free_unpacked(env, NULL);

    if (sd_channel_set_crypto_encrypt(channel, &keys, &remote_keys,
                nonce, response->nonce.data) < 0) {
        puts("Failed enabling encryption");
        return -1;
    }

    encryption_negotiation_message__free_unpacked(response, NULL);

    return 0;
}

int query(struct sd_channel *channel)
{
    QueryResults *result;
    char pk[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    size_t i, j;

    if (negotiate_encryption(channel) < 0) {
        puts("Unable to negotiate encryption");
        return -1;
    }

    sodium_bin2hex(pk, sizeof(pk),
            channel->remote_keys.sign, sizeof(channel->remote_keys.sign));

    if (sd_channel_receive_protobuf(channel, &query_results__descriptor,
            (ProtobufCMessage **) &result) < 0) {
        puts("Could not receive query results");
        return -1;
    }

    printf("%s\n"
           "\tname:     %s\n"
           "\ttype:     %s\n"
           "\tsubtype:  %s\n"
           "\tversion:  %s\n"
           "\tlocation: %s\n",
           pk,
           result->name,
           result->type,
           result->subtype,
           result->version,
           result->location);

    for (i = 0; i < result->n_parameters; i++) {
        QueryResults__Parameter *param = result->parameters[i];
        printf("\tparam:    %s\n", param->key);

        for (j = 0; j < param->n_value; j++)
            printf("\t          %s\n", param->value[j]);
    }

    query_results__free_unpacked(result, NULL);

    return 0;
}

int main(int argc, char *argv[])
{
    const char *config, *key, *host, *port;
    struct sd_channel channel;

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

    if (sd_channel_init_from_host(&channel, host, port, SD_CHANNEL_TYPE_TCP) < 0) {
        puts("Could not initialize channel");
        return -1;
    }

    if (sd_channel_connect(&channel) < 0) {
        puts("Could not connect to server");
        return -1;
    }

    if (query(&channel) < 0) {
        puts("Could not query server");
        return -1;
    }

    sd_channel_close(&channel);

    return 0;
}
