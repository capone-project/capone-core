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

#include "capone/common.h"
#include "capone/cmdparse.h"
#include "capone/log.h"

static int parse_option(struct cpn_cmdparse_opt *opt, int argc, const char *argv[])
{
    switch (opt->type) {
        case CPN_CMDPARSE_TYPE_ACTION:
            if (cpn_cmdparse_parse(opt->value.action_opts, argc - 1, argv + 1) < 0) {
                cpn_log(LOG_LEVEL_ERROR, "Cannot parse action %s", argv[0]);
                return -1;
            }

            return argc;
        case CPN_CMDPARSE_TYPE_COUNTER:
            opt->value.counter++;
            return 0;
        case CPN_CMDPARSE_TYPE_SIGKEY:
            {
                struct cpn_sign_key_public key;

                if (argc < 2) {
                    cpn_log(LOG_LEVEL_ERROR, "No key for option %s", argv[0]);
                    return -1;
                }

                if (cpn_sign_key_public_from_hex(&key, argv[1]) < 0) {
                    cpn_log(LOG_LEVEL_ERROR, "Invalid key %s for option %s",
                            argv[1], argv[0]);
                    return -1;
                }
            }

            return 1;
        case CPN_CMDPARSE_TYPE_STRING:
            if (argc < 2) {
                cpn_log(LOG_LEVEL_ERROR, "No value for option %s", argv[0]);
                return -1;
            }

            opt->value.string = argv[1];

            return 1;
        case CPN_CMDPARSE_TYPE_STRINGLIST:
            if (argc < 2) {
                cpn_log(LOG_LEVEL_ERROR, "No string list for option %s", argv[0]);
                return -1;
            }

            opt->value.stringlist.argc = argc - 1;
            opt->value.stringlist.argv = argv + 1;

            return argc;
        case CPN_CMDPARSE_TYPE_UINT32:
            {
                uint32_t value;

                if (argc < 2) {
                    cpn_log(LOG_LEVEL_ERROR, "No value for option %s", argv[0]);
                    return -1;
                }

                if (parse_uint32t(&value, argv[1]) < 0) {
                    cpn_log(LOG_LEVEL_ERROR, "Invalid value %s for option %s",
                            argv[1], argv[0]);
                    return -1;
                }

                opt->value.uint32 = value;
            }

            return 1;
        case CPN_CMDPARSE_TYPE_END:
            cpn_log(LOG_LEVEL_ERROR, "Unknown option %s", argv[0]);
            return -1;
    }

    return -1;
}

int cpn_cmdparse_parse(struct cpn_cmdparse_opt *opts, int argc, const char *argv[])
{
    int i, processed;
    struct cpn_cmdparse_opt *opt;

    for (i = 0; i < argc; i++) {
        for (opt = opts; opt->type != CPN_CMDPARSE_TYPE_END; opt++) {
            if (opt->short_name && argv[i][0] == '-' && argv[i][1] == opt->short_name && argv[i][2] == '\0') {
                break;
            } else if (opt->long_name && !strcmp(argv[i], opt->long_name)) {
                break;
            }
        }

        if ((processed = parse_option(opt, argc - i, argv + i)) < 0)
            return -1;
        opt->set = true;

        i += processed;
    }

    for (opt = opts; opt->type != CPN_CMDPARSE_TYPE_END; opt++) {
        if (!opt->set && !opt->optional) {
            cpn_log(LOG_LEVEL_ERROR, "Required argument %s not set", opt->long_name);
            return -1;
        }
    }

    return 0;
}
