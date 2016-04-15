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

#ifndef SD_LIB_PROTO_H
#define SD_LIB_PROTO_H

#include "lib/channel.h"
#include "lib/service.h"

enum sd_connection_type {
    SD_CONNECTION_TYPE_QUERY,
    SD_CONNECTION_TYPE_CONNECT,
    SD_CONNECTION_TYPE_REQUEST
};

struct sd_query_results {
    char *name;
    char *category;
    char *type;
    char *version;
    char *location;
    char *port;
    struct sd_service_parameter *params;
    size_t nparams;
};

int sd_proto_initiate_connection(struct sd_channel *channel,
        const char *host,
        const char *port,
        const struct sd_sign_key_pair *local_keys,
        const struct sd_sign_key_public *remote_key,
        enum sd_connection_type type);
int sd_proto_receive_connection_type(enum sd_connection_type *out,
        struct sd_channel *channel);

int sd_proto_initiate_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        const struct sd_sign_key_public *remote_sign_key);
int sd_proto_await_encryption(struct sd_channel *channel,
        const struct sd_sign_key_pair *sign_keys,
        struct sd_sign_key_public *remote_sign_key);

int sd_proto_send_query(struct sd_query_results *out,
        struct sd_channel *channel);
int sd_proto_answer_query(struct sd_channel *channel,
        const struct sd_service *service,
        const struct sd_sign_key_public *remote_key,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist);
void sd_query_results_free(struct sd_query_results *results);

int sd_proto_send_request(struct sd_session *out,
        struct sd_channel *channel,
        const struct sd_sign_key_public *requester,
        const struct sd_service_parameter *params, size_t nparams);
int sd_proto_answer_request(struct sd_channel *channel,
        const struct sd_sign_key_public *remote_key,
        const struct sd_sign_key_public *whitelist,
        size_t nwhitelist);

int sd_proto_initiate_session(struct sd_channel *channel, int sessionid);
int sd_proto_handle_session(struct sd_channel *channel,
        const struct sd_sign_key_public *remote_key,
        const struct sd_service *service,
        const struct cfg *cfg);

#endif
