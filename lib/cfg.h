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

#include <stdint.h>
#include <stddef.h>

enum cfg_entry_type {
    CFG_ENTRY_TYPE_UINT,
    CFG_ENTRY_TYPE_INT,
    CFG_ENTRY_TYPE_STRING,
};

struct cfg_entry {
    char *name;
    char *value;
};

struct cfg_section {
    char *name;
    struct cfg_entry *entries;
    size_t numentries;
};

struct cfg {
    struct cfg_section *sections;
    size_t numsections;
};

int cfg_parse(struct cfg *c, const char *path);
int cfg_parse_string(struct cfg *c, const char *ptr, size_t len);
void cfg_free(struct cfg *c);

const struct cfg_section *cfg_get_section(const struct cfg *c, const char *name);
const struct cfg_entry *cfg_get_entry(const struct cfg_section *s, const char *name);

char *cfg_get_str_value(const struct cfg *c, const char *section, const char *key);
int cfg_get_int_value(const struct cfg *c, const char *section, const char *key);
