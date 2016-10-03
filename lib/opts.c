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

#include "config.h"

#include "capone/common.h"
#include "capone/log.h"
#include "capone/opts.h"

static int parse_option(struct cpn_opt *opt, int argc, const char *argv[])
{
    switch (opt->type) {
        case CPN_OPTS_TYPE_ACTION:
            if (cpn_opts_parse(opt->value.action_opts, argc - 1, argv + 1) < 0) {
                cpn_log(LOG_LEVEL_ERROR, "Cannot parse action %s", argv[0]);
                return -1;
            }

            return argc;
        case CPN_OPTS_TYPE_COUNTER:
            opt->value.counter++;
            return 0;
        case CPN_OPTS_TYPE_SIGKEY:
            {
                struct cpn_sign_pk key;

                if (argc < 2) {
                    cpn_log(LOG_LEVEL_ERROR, "No key for option %s", argv[0]);
                    return -1;
                }

                if (cpn_sign_pk_from_hex(&key, argv[1]) < 0) {
                    cpn_log(LOG_LEVEL_ERROR, "Invalid key %s for option %s",
                            argv[1], argv[0]);
                    return -1;
                }

                memcpy(&opt->value.sigkey, &key, sizeof(key));
            }

            return 1;
        case CPN_OPTS_TYPE_STRING:
            if (argc < 2) {
                cpn_log(LOG_LEVEL_ERROR, "No value for option %s", argv[0]);
                return -1;
            }

            opt->value.string = argv[1];

            return 1;
        case CPN_OPTS_TYPE_STRINGLIST:
            if (argc < 2) {
                cpn_log(LOG_LEVEL_ERROR, "No string list for option %s", argv[0]);
                return -1;
            }

            opt->value.stringlist.argc = argc - 1;
            opt->value.stringlist.argv = argv + 1;

            return argc;
        case CPN_OPTS_TYPE_UINT32:
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
        case CPN_OPTS_TYPE_END:
            cpn_log(LOG_LEVEL_ERROR, "Unknown option %s", argv[0]);
            return -1;
    }

    return -1;
}

const union cpn_opt_value *cpn_opts_get(const struct cpn_opt *opts,
        char shortopt, const char *longopt)
{
    const struct cpn_opt *opt;

    for (opt = opts; opt && opt->type != CPN_OPTS_TYPE_END; opt++) {
        if (shortopt && shortopt != opt->short_name)
            continue;
        if (longopt && strcmp(longopt, opt->long_name))
            continue;
        if (!opt->set)
            return NULL;

        return &opt->value;
    }

    return NULL;
}

int cpn_opts_parse(struct cpn_opt *opts, int argc, const char *argv[])
{
    int i, processed;
    struct cpn_opt *opt;

    for (i = 0; i < argc; i++) {
        for (opt = opts; opt && opt->type != CPN_OPTS_TYPE_END; opt++) {
            if (opt->short_name && argv[i][0] == '-' && argv[i][1] == opt->short_name && argv[i][2] == '\0') {
                break;
            } else if (opt->long_name && !strcmp(argv[i], opt->long_name)) {
                break;
            }
        }

        if (!opt) {
            cpn_log(LOG_LEVEL_ERROR, "Unknown option %s", argv[0]);
            return -1;
        }

        if ((processed = parse_option(opt, argc - i, argv + i)) < 0)
            return -1;
        opt->set = true;

        i += processed;
    }

    for (opt = opts; opt && opt->type != CPN_OPTS_TYPE_END; opt++) {
        if (!opt->set && !opt->optional) {
            cpn_log(LOG_LEVEL_ERROR, "Required argument %s not set", opt->long_name);
            return -1;
        }
    }

    return 0;
}

int cpn_opts_parse_cmd(struct cpn_opt *opts, int argc, const char *argv[])
{
    const char *executable = argv[0];
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) {
            cpn_opts_version(executable, stdout);
            return -1;
        } else if (!strcmp(argv[i], "--help")) {
            cpn_opts_usage(opts, executable, stderr);
            return -1;
        }
    }

    return cpn_opts_parse(opts, argc - 1, argv + 1);
}

static void print_arguments(const struct cpn_opt *opts, FILE *out, int indent)
{
    const struct cpn_opt *it;
    int i;

    for (it = opts; it && it->type != CPN_OPTS_TYPE_END; it++) {
        if (it->type == CPN_OPTS_TYPE_ACTION)
            continue;

        for (i = indent; i; i--)
            fputc('\t', out);

        if (it->short_name && it->long_name)
            fprintf(out, "-%c, %s", it->short_name, it->long_name);
        else if (it->short_name)
            fprintf(out, "-%c", it->short_name);
        else
            fputs(it->long_name, out);

        switch (it->type) {
            case CPN_OPTS_TYPE_SIGKEY:
                fprintf(out, " <%s>", it->argname ? it->argname : "KEY");
                break;
            case CPN_OPTS_TYPE_STRING:
                fprintf(out, " <%s>", it->argname ? it->argname : "VALUE");
                break;
            case CPN_OPTS_TYPE_STRINGLIST:
                fprintf(out, " [%s...]", it->argname ? it->argname : "VALUE");
                break;
            case CPN_OPTS_TYPE_UINT32:
                fprintf(out, " <%s>", it->argname ? it->argname : "UNSIGNED_INT");
                break;
            default:
                break;
        }

        if (it->description) {
            fputc('\n', out);
            for (i = indent; i; i--)
                fputc('\t', out);
            fprintf(out, "\t%s", it->description);
        }

        fputc('\n', out);
    }
}

static bool has_options(const struct cpn_opt *opts)
{
    const struct cpn_opt *it;
    for (it = opts; it && it->type != CPN_OPTS_TYPE_END; it++)
        if (it->type != CPN_OPTS_TYPE_ACTION)
            return true;
    return false;
}

static bool has_actions(const struct cpn_opt *opts)
{
    const struct cpn_opt *it;
    for (it = opts; it && it->type != CPN_OPTS_TYPE_END; it++)
        if (it->type == CPN_OPTS_TYPE_ACTION)
            return true;
    return false;
}

static void print_header(const struct cpn_opt *opts, const char *name, const char *description, FILE *out)
{
    const struct cpn_opt *it;

    fputs(name, out);

    if (has_options(opts))
        fputs(" [OPTIONS...]", out);

    if (has_actions(opts)) {
        bool first_action = true;

        fputs(" (", out);
        for (it = opts; it && it->type != CPN_OPTS_TYPE_END; it++) {
            if (it->type == CPN_OPTS_TYPE_ACTION) {
                fprintf(out, "%s%s", first_action ? "" : "|", it->long_name);
                first_action = false;
            }
        }
        fputs(")", out);
    }

    if (description) {
        fprintf(out, ": %s", description);
    }

    fputc('\n', out);
}

static void print_actions(const struct cpn_opt *opts, FILE *out, int indent)
{
    const struct cpn_opt *it;
    int i;

    for (it = opts; it && it->type != CPN_OPTS_TYPE_END; it++) {
        if (it->type != CPN_OPTS_TYPE_ACTION)
            continue;

        for (i = indent; i; i--)
            fputc('\t', out);
        print_header(it->value.action_opts, it->long_name, it->description, out);
        print_arguments(it->value.action_opts, out, indent + 1);
        if (has_actions(it) && has_options(it))
            fputc('\n', out);
        print_actions(it->value.action_opts, out, indent + 1);
    }
}

void cpn_opts_usage(const struct cpn_opt *opts,
        const char *executable, FILE *out)
{
    fputs("USAGE: ", out);
    print_header(opts, executable, NULL, out);
    if (has_actions(opts) || has_options(opts))
        fputc('\n', out);
    print_arguments(opts, out, 1);
    if (has_actions(opts) && has_options(opts))
        fputc('\n', out);
    print_actions(opts, out, 1);
}

void cpn_opts_version(const char *executable, FILE *out)
{
    fprintf(out,
            "%s %s\n"
            "Copyright (C) 2016 Patrick Steinhardt\n"
            "License GPLv3: GNU GPL version 3 <http://gnu.org/licenses/gpl.html>.\n"
            "This is free software; you are free to change and redistribute it.\n"
            "There is NO WARRANTY, to the extent permitted by the law.\n",
            executable, CPN_VERSION);
}
