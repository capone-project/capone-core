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

#ifndef SD_LIB_CAPS_H
#define SD_LIB_CAPS_H

#include <stdbool.h>
#include "lib/keys.h"

enum sd_cap_rights {
    SD_CAP_RIGHT_EXEC = 1 << 0,
    SD_CAP_RIGHT_TERM = 1 << 1
};

struct sd_cap {
    uint32_t objectid;
    uint32_t rights;
    uint32_t secret;
};

int sd_caps_add(uint32_t objectid);
int sd_caps_delete(uint32_t objectid);
int sd_caps_create_reference(struct sd_cap *out, uint32_t objectid, uint32_t rights, const struct sd_sign_key_public *key);
int sd_caps_verify(const struct sd_cap *ref, const struct sd_sign_key_public *key, uint32_t rights);

#endif
