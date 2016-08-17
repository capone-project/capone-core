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
 * \defgroup cpn-cmdparse Parser for command line arguments
 * \ingroup cpn-lib
 *
 * @brief Module handling parsing of command line arguments
 *
 * This module provides the ability to parse command line
 * arguments provided on the command line interface by users. It
 * exposes a single structure through which allowed command line
 * options are specified, which is subsequently used to parse the
 * arguments.
 *
 * @{
 */

#ifndef CAPONE_OPTS_H
#define CAPONE_OPTS_H

#include <stdbool.h>
#include <inttypes.h>

#include "capone/keys.h"

/**
 * Type of command line arguments
 */
enum cpn_opts_type {
    /** A sub-action, usually used to distinguish different modes
     * of operation inside a single executable. Only a single
     * sub-action can be chosen by the user. The program is able
     * to determine the chosen subaction by inspcecting for each
     * action, if it is set or not.
     */
    CPN_OPTS_TYPE_ACTION,

    /** A simple counter option. Counters do not accept
     * arguments, but may be specified multiple times, causing
     * an integer to be counted up. */
    CPN_OPTS_TYPE_COUNTER,

    /** A public signature key is hex-format. */
    CPN_OPTS_TYPE_SIGKEY,

    /** A simple string argument. */
    CPN_OPTS_TYPE_STRING,

    /** A list of strings. When string lists are used, the user
     * is only allowed to put them at the end of the command
     * line. The string list is initiated by the string list
     * option, leading all following arguments to be added to
     * this list. */
    CPN_OPTS_TYPE_STRINGLIST,

    /** An unsigned integer. */
    CPN_OPTS_TYPE_UINT32,

    /** Each array of `struct cpn_opt` must be
     * terminated by this. */
    CPN_OPTS_TYPE_END
};

#define CPN_OPTS_OPT_ACTION(action, desc, opts) \
    { 0, (action), (desc), NULL, CPN_OPTS_TYPE_ACTION, {(opts)}, true, false }
#define CPN_OPTS_OPT_COUNTER(s, l, desc) \
    { (s), (l), (desc), NULL, CPN_OPTS_TYPE_COUNTER, {NULL}, true, false }
#define CPN_OPTS_OPT_SIGKEY(s, l, desc, arg, optional) \
    { (s), (l), (desc), (arg), CPN_OPTS_TYPE_SIGKEY, {NULL}, (optional), false }
#define CPN_OPTS_OPT_STRING(s, l, desc, arg, optional) \
    { (s), (l), (desc), (arg), CPN_OPTS_TYPE_STRING, {NULL}, (optional), false }
#define CPN_OPTS_OPT_STRINGLIST(s, l, desc, arg, optional) \
    { (s), (l), (desc), (arg), CPN_OPTS_TYPE_STRINGLIST, {NULL}, (optional), false }
#define CPN_OPTS_OPT_UINT32(s, l, desc, arg, optional) \
    { (s), (l), (desc), (arg), CPN_OPTS_TYPE_UINT32, {NULL}, (optional), false }
#define CPN_OPTS_OPT_END                    \
    { 0, NULL, NULL, NULL, CPN_OPTS_TYPE_END, {NULL}, false, false }

/** @brief A simple list of arguments
 *
 * This structure contains a pointer to the first argument of the
 * string list as well as a count of how many arguments are added
 * to the list.
 */
struct cpn_opts_stringlist {
    const char **argv;
    int argc;
};

/** @brief Structure specifying all available options
 *
 * This structure is used to define all available parameters. To
 * use the parsing functions, one first defines an array of all
 * parsing options, which are then passed to the parsing
 * function along with the actual command line arguments. The
 * parser then parses the arguments, storing the arguments inside
 * the structure's value field.
 *
 * The value field is a union of all possible argument types
 * specified by the enum `cpn_opts_type`. It is only valid to
 * access the value corresponding to the given type.
 *
 * Note that the array of options is always required to be
 * terminated with `CPN_OPTS_OPT_END`.
 */
struct cpn_opt {
    char short_name;
    const char *long_name;
    const char *description;
    const char *argname;
    enum cpn_opts_type type;
    union {
        struct cpn_opt *action_opts;
        uint32_t counter;
        struct cpn_sign_key_public sigkey;
        const char *string;
        struct cpn_opts_stringlist stringlist;
        uint32_t uint32;
    } value;
    bool optional;
    bool set;
};

/** @brief Parse command line arguments with specified options
 *
 * Given a number of command line arguments, parse them according
 * to the options passed in.
 *
 * The function tries to parse the complete command line
 * arguments. That is if any of the given arguments is not
 * matched, the function will fail and return an error.
 * Similarly, if any of the options specified as being required
 * is not set by the command line arguments, the function will
 * fail, as well.
 *
 * @param[in] opts Options specifying the format of command line
 *            arguments. This will also contain parsed values
 *            after successful execution.
 * @param[in] argc Number of arguments contained in the `argv`
 *            array.
 * @param[in] argv Command line arguments.
 *
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_opts_parse(struct cpn_opt *opts, int argc, const char *argv[]);

/** @brief Parse command line including executable name
 *
 * In contrast to `cpn_opts_parse`, this function expects the
 * arguments to contain the current executable name as a first
 * argument. Furthermore, it will also print out usage as well as
 * version information if requested by the user and return an
 * error if so.
 *
 * @param[in] opts Options specifying the format of command line
 *            arguments. This will also contain parsed values
 *            after successful execution.
 * @param[in] argc Number of arguments contained in the `argv`
 *            array.
 * @param[in] argv Command line arguments.
 *
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_opts_parse_cmd(struct cpn_opt *opts, int argc, const char *argv[]);

/** @brief Print usage to the terminal
 *
 * Using the specified options, print usage information to the
 * command line.
 *
 * @param[in] opts Options specifying the format of command line
 *            arguments.
 * @param[in] executable Name of the executable to use when
 *            printing usage information.
 * @param[in] error Whether to print to <code>stderr</code>
 *            instead to <code>stdout</code>
 */
void cpn_opts_usage(const struct cpn_opt *opts, const char *executable, bool error);

/** @brief Print version information */
void cpn_opts_version(const char *executable);

#endif

/** @} */
