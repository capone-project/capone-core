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

int cpn_cmdparse_parse(struct cpn_cmdparse_opt *opts, int argc, const char *argv[])
{
    int i;
    struct cpn_cmdparse_opt *opt;

    for (i = 0; i < argc; i++) {
        for (opt = opts; opt->type != CPN_CMDPARSE_TYPE_END; opt++) {
            if (opt->short_name && argv[i][0] == '-' && argv[i][1] == opt->short_name && argv[i][2] == '\0') {
                break;
            } else if (opt->long_name && !strcmp(argv[i], opt->long_name)) {
                break;
            }
        }

        switch (opt->type) {
            case CPN_CMDPARSE_TYPE_ACTION:
                if (cpn_cmdparse_parse(opt->value.action_opts, argc - i - 1, argv + i + 1) < 0) {
                    cpn_log(LOG_LEVEL_ERROR, "Cannot parse action %s", argv[i]);
                    return -1;
                }
                i = argc;
                break;
            case CPN_CMDPARSE_TYPE_COUNTER:
                opt->value.counter++;
                break;
            case CPN_CMDPARSE_TYPE_SIGKEY:
                {
                    struct cpn_sign_key_public key;
                    if (++i >= argc) {
                        cpn_log(LOG_LEVEL_ERROR, "No key for option %s", argv[i - 1]);
                        return -1;
                    }

                    if (cpn_sign_key_public_from_hex(&key, argv[i]) < 0) {
                        cpn_log(LOG_LEVEL_ERROR, "Invalid key %s for option %s",
                                argv[i], argv[i - 1]);
                        return -1;
                    }
                }
                break;
            case CPN_CMDPARSE_TYPE_STRING:
                if (++i >= argc) {
                    cpn_log(LOG_LEVEL_ERROR, "No value for option %s", argv[i - 1]);
                    return -1;
                }
                opt->value.string = argv[i];
                break;
            case CPN_CMDPARSE_TYPE_STRINGLIST:
                if (++i >= argc) {
                    cpn_log(LOG_LEVEL_ERROR, "No string list for option %s", argv[i - 1]);
                    return -1;
                }
                opt->value.stringlist.argc = argc - i;
                opt->value.stringlist.argv = argv + i;
                i = argc;
                break;
            case CPN_CMDPARSE_TYPE_UINT32:
                {
                    uint32_t value;

                    if (++i >= argc) {
                        cpn_log(LOG_LEVEL_ERROR, "No value for option %s", argv[i - 1]);
                        return -1;
                    }

                    if (parse_uint32t(&value, argv[i]) < 0) {
                        cpn_log(LOG_LEVEL_ERROR, "Invalid value %s for option %s",
                                argv[i], argv[i - 1]);
                        return -1;
                    }

                    opt->value.uint32 = value;
                }
                break;
            case CPN_CMDPARSE_TYPE_END:
                cpn_log(LOG_LEVEL_ERROR, "Unknown option %s", argv[i]);
                return -1;
        }

        opt->set = true;
    }

    for (opt = opts; opt->type != CPN_CMDPARSE_TYPE_END; opt++) {
        if (!opt->set && !opt->optional) {
            cpn_log(LOG_LEVEL_ERROR, "Required argument %s not set", opt->long_name);
            return -1;
        }
    }

    return 0;
}
