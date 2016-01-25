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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "cfg.h"
#include "log.h"

static int map_file(char **out, size_t *outlen, const char *path)
{
    int fd = -1, ret = 0;
    char *ptr = NULL;
    struct stat st;

    ret = stat(path, &st);
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not stat file: %s",
                strerror(errno));
        goto out;
    }

    fd = open(path,  O_RDONLY);
    if (fd < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not open file: %s",
                strerror(errno));
        ret = fd;
        goto out;
    }

    ptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Could not mmap file: %s",
                strerror(errno));
        ret = -1;
        goto out;
    }

    *out = ptr;
    *outlen = st.st_size;

out:
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}

static char *next_line(const char *ptr, size_t len)
{
    char *newline;

    newline = memchr(ptr, '\n', len);
    if (newline == NULL)
        return NULL;

    return newline + 1;
}

enum line_type {
    LINE_TYPE_EOF,
    LINE_TYPE_EMPTY,
    LINE_TYPE_SECTION,
    LINE_TYPE_CONFIG,
    LINE_TYPE_INVALID,
};

static int parse_section(char *section, size_t maxlen, const char *line, size_t len)
{
    const char *ptr;

    assert(*line == '[');
    assert(*(line + len) == ']');

    ptr = line + 1;
    for (ptr = line + 1; ptr < line + len; ptr++) {
        if (!isalnum(*ptr)) {
            sd_log(LOG_LEVEL_ERROR, "Invalid section: '%s'", section);
            return -1;
        }
    }

    if (len > maxlen) {
        sd_log(LOG_LEVEL_ERROR, "Section longer than maxlen: '%s'", section);
        return -1;
    }

    memcpy(section, line + 1, len - 1);
    section[len - 1] = '\0';

    return 0;
}

static int parse_config(char *key, size_t keylen, char *value, size_t valuelen, const char *line, size_t len)
{
    const char *ptr;

    ptr = memchr(line, '=', len);
    assert(ptr);

    if (ptr - line >= (ssize_t) keylen) {
        sd_log(LOG_LEVEL_ERROR, "Key longer than maxlen: '%s'", line);
        return -1;
    }

    if (len - (ptr - line) >= valuelen) {
        sd_log(LOG_LEVEL_ERROR, "Value longer than maxlen: '%s'", line);
        return -1;
    }

    memcpy(key, line, ptr - line);
    key[ptr - line] = '\0';
    memcpy(value, ptr + 1, len - (ptr - line));
    value[len - (ptr - line)] = '\0';

    return 0;
}

static enum line_type parse_line(char *key, size_t keylen, char *value, size_t valuelen, const char *line, size_t len)
{
    const char *ptr, *start, *end;
    size_t linelen;

    if (len == 0) {
        return LINE_TYPE_EOF;
    }

    /* Find line end */
    for (ptr = line; *ptr && *ptr != '\n' && (ptr - line) < (ssize_t) len; ptr++);

    /* Trim trailing whitespace */
    for (end = ptr; (*end == '\0' || isspace(*end)) && end > line; end--);
    /* Trim leading whitespace */
    for (start = line; isspace(*start) && start < end; start++);

    linelen = end - start;

    if (start == end) {
        return LINE_TYPE_EMPTY;
    }

    if (*start == '[' && *end == ']') {
        parse_section(key, keylen, start, linelen);
        return LINE_TYPE_SECTION;
    } else if ((ptr = memchr(start, '=', linelen)) != NULL) {
        parse_config(key, keylen, value, valuelen, start, linelen);
        return LINE_TYPE_CONFIG;
    }

    return LINE_TYPE_INVALID;
}

static struct cfg_section *add_section(struct cfg *c, const char *section)
{
    struct cfg_section *s;
    int len;

    c->numsections += 1;
    c->sections = realloc(c->sections, sizeof(struct cfg_section) * c->numsections);

    s = &c->sections[c->numsections - 1];
    memset(s, '\0', sizeof(struct cfg_section));

    len = strlen(section);
    s->name = malloc(len + 1);
    memcpy(s->name, section, len);
    s->name[len + 1] = '\0';

    return s;
}

static void add_config(struct cfg_section *s, const char *key, const char *value)
{
    struct cfg_entry *e;
    int len;

    s->numentries += 1;
    s->entries = realloc(s->entries, sizeof(struct cfg_entry) * s->numentries);

    e = &s->entries[s->numentries - 1];
    memset(e, '\0', sizeof(struct cfg_entry));

    len = strlen(key);
    e->name = malloc(len + 1);
    memcpy(e->name, key, len);
    e->name[len + 1] = '\0';

    len = strlen(value);
    e->value = malloc(len + 1);
    memcpy(e->value, value, len);
    e->value[len + 1] = '\0';

    return;
}

int cfg_parse_string(struct cfg *c, const char *ptr, size_t len)
{
    struct cfg_section *section = NULL;
    const char *line = ptr;
    int ret = 0;

    memset(c, '\0', sizeof(struct cfg));

    do {
        char key[128], value[1024];
        enum line_type type;

        len = len - (line - ptr);

        type = parse_line(key, sizeof(key), value, sizeof(value), line, len);
        switch (type) {
            case LINE_TYPE_EOF:
                break;
            case LINE_TYPE_EMPTY:
                continue;
            case LINE_TYPE_SECTION:
                section = add_section(c, key);
                break;
            case LINE_TYPE_CONFIG:
                if (!section) {
                    sd_log(LOG_LEVEL_ERROR, "Unable to add config without section: '%s'",
                            line);
                    ret = -1;
                    goto out;
                }
                add_config(section, key, value);
                break;
            case LINE_TYPE_INVALID:
                ret = -1;
                goto out;
        }
    } while ((line = next_line(line, len)) != NULL);

out:

    return ret;
}

int cfg_parse(struct cfg *c, const char *path)
{
    char *ptr;
    size_t len;
    int ret;

    ret = map_file(&ptr, &len, path);
    if (ret < 0) {
        return ret;
    }

    ret = cfg_parse_string(c, ptr, len);

    munmap(ptr, len);

    return ret;
}

void cfg_free(struct cfg *c)
{
    unsigned section, entry;

    for (section = 0; section < c->numsections; section++) {
        struct cfg_section *s = &c->sections[section];

        for (entry = 0; entry < s->numentries; entry++) {
            struct cfg_entry *e = &s->entries[entry];

            free(e->name);
            free(e->value);

        }

        free(s->name);
        free(s->entries);
    }


}
