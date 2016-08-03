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

static void print_arguments(const struct cpn_cmdparse_opt *opts, FILE *out, int indent)
{
    const struct cpn_cmdparse_opt *it;
    int i;

    for (it = opts; it && it->type != CPN_CMDPARSE_TYPE_END; it++) {
        if (it->type == CPN_CMDPARSE_TYPE_ACTION)
            continue;

        for (i = indent; i; i--)
            fputc('\t', out);

        if (it->short_name && it->long_name)
            fprintf(out, "-%c, %s", it->short_name, it->long_name);
        else if (it->short_name)
            fputc(it->short_name, out);
        else
            fputs(it->long_name, out);

        switch (it->type) {
            case CPN_CMDPARSE_TYPE_SIGKEY:
                fputs(" <SIGNATURE_KEY>", out);
                break;
            case CPN_CMDPARSE_TYPE_STRING:
                fputs(" <VALUE>", out);
                break;
            case CPN_CMDPARSE_TYPE_STRINGLIST:
                fputs(" <VALUE> [<VALUE>]+", out);
                break;
            case CPN_CMDPARSE_TYPE_UINT32:
                fputs(" <UNSIGNED_INTEGER>", out);
                break;
            default:
                break;
        }

        fputc('\n', out);
    }
}

static void print_header(const struct cpn_cmdparse_opt *opts, const char *name, FILE *out)
{
    const struct cpn_cmdparse_opt *it;
    bool has_actions = 0, has_opts = 0;

    fputs(name, out);

    for (it = opts; it && it->type != CPN_CMDPARSE_TYPE_END; it++) {
        switch (it->type) {
            case CPN_CMDPARSE_TYPE_ACTION:
                has_actions = 1;
                continue;
            default:
                has_opts = 1;
                break;
        }
    }

    if (has_opts)
        fputs(" [<OPTS>]", out);

    if (has_actions) {
        bool first_action = true;

        fputs(" (", out);
        for (it = opts; it && it->type != CPN_CMDPARSE_TYPE_END; it++) {
            if (it->type == CPN_CMDPARSE_TYPE_ACTION) {
                fprintf(out, "%s%s", first_action ? "" : "|", it->long_name);
                first_action = false;
            }
        }
        fputs(")", out);
    }

    fputc('\n', out);
}

static void print_actions(const struct cpn_cmdparse_opt *opts, FILE *out, int indent)
{
    const struct cpn_cmdparse_opt *it;
    int i;

    for (it = opts; it && it->type != CPN_CMDPARSE_TYPE_END; it++) {
        if (it->type != CPN_CMDPARSE_TYPE_ACTION)
            continue;

        for (i = indent; i; i--)
            fputc('\t', out);
        print_header(it->value.action_opts, it->long_name, out);
        print_arguments(it->value.action_opts, out, indent + 1);
        fputc('\n', out);
        print_actions(it->value.action_opts, out, indent + 1);
    }
}

void cpn_cmdparse_usage(const struct cpn_cmdparse_opt *opts,
        const char *executable, bool error)
{
    FILE *out = error ? stderr : stdout;

    fputs("USAGE: ", out);
    print_header(opts, executable, out);
    print_arguments(opts, out, 1);
    fputc('\n', out);
    print_actions(opts, out, 1);
}
