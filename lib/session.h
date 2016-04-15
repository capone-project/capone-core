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

#ifndef SD_SESSION_H
#define SD_SESSION_H

#include <inttypes.h>

#include "lib/keys.h"

struct sd_session {
    uint32_t sessionid;
    struct sd_sign_key_public identity;

    struct sd_service_parameter *parameters;
    size_t nparameters;
};

int sd_sessions_init(void);

int sd_sessions_add(uint32_t sessionid,
        const struct sd_sign_key_public *identity,
        struct sd_service_parameter *params,
        size_t nparams);
int sd_sessions_remove(struct sd_session *out,
        uint32_t sessionid,
        const struct sd_sign_key_public *identity);
int sd_sessions_clear(void);

void sd_session_free(struct sd_session *session);

#endif
