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

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>

#include <cmocka.h>

#include "lib/log.h"

#include "cfg.h"
#include "channel.h"
#include "common.h"
#include "server.h"

int main(int argc, char *argv[])
{
    if (argc != 1 && (argc == 2 && strcmp(argv[1], "--verbose"))) {
        printf("USAGE: %s [--verbose]", argv[0]);
        return -1;
    }

    if (argc == 2 && !strcmp(argv[1], "--verbose"))
        sd_log_set_level(LOG_LEVEL_VERBOSE);
    else
        sd_log_set_level(LOG_LEVEL_NONE);

    cfg_test_run_suite();
    channel_test_run_suite();
    common_test_run_suite();
    server_test_run_suite();

    return 0;
}
