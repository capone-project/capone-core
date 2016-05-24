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

/**
 * \defgroup sd-cfg Configuration
 * \ingroup sd-lib
 * @{
 */

#ifndef SD_LIB_CFG_H
#define SD_LIB_CFG_H

#include <stdint.h>
#include <stddef.h>

struct sd_cfg_entry {
    char *name;
    char *value;
};

struct sd_cfg_section {
    char *name;
    struct sd_cfg_entry *entries;
    size_t numentries;
};

struct sd_cfg {
    struct sd_cfg_section *sections;
    size_t numsections;
};

int sd_cfg_parse(struct sd_cfg *c, const char *path);
int sd_cfg_parse_string(struct sd_cfg *c, const char *ptr, size_t len);
void sd_cfg_free(struct sd_cfg *c);

const struct sd_cfg_section *sd_cfg_get_section(const struct sd_cfg *c, const char *name);
const struct sd_cfg_entry *sd_cfg_get_entry(const struct sd_cfg_section *s, const char *name);

char *sd_cfg_get_str_value(const struct sd_cfg *c, const char *section, const char *key);
int sd_cfg_get_int_value(const struct sd_cfg *c, const char *section, const char *key);

#endif

/** @} */
