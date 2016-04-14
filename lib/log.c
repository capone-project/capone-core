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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "log.h"

static enum log_level current_log_level = LOG_LEVEL_DEBUG;

static const char *log_levels[] = {
    "DEBUG",
    "VERBOSE",
    "WARNING",
    "ERROR",
};

void sd_log(enum log_level lvl, const char *msgformat, ...)
{
    char msg[3978], buf[4096], date[128];
    time_t t;
    struct tm *tm;
    va_list ap;

    if (lvl < current_log_level)
        return;

    t = time(NULL);
    tm = localtime(&t);
    strftime(date, sizeof(date), "%H:%M:%S", tm);

    va_start(ap, msgformat);
    vsnprintf(msg, sizeof(msg), msgformat, ap);
    va_end(ap);

    snprintf(buf, sizeof(buf), "%s - %s: %s", date, log_levels[lvl], msg);

    puts(buf);
}

void sd_log_set_level(enum log_level lvl)
{
    current_log_level = lvl;
}
