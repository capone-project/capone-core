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

#ifndef CAPONE_CMDPARSE_H
#define CAPONE_CMDPARSE_H

#include <stdbool.h>
#include <inttypes.h>

#include "capone/keys.h"

/**
 * Type of command line arguments
 */
enum cpn_cmdparse_type {
    /** A sub-action, usually used to distinguish different modes
     * of operation inside a single executable. Only a single
     * sub-action can be chosen by the user. The program is able
     * to determine the chosen subaction by inspcecting for each
     * action, if it is set or not.
     */
    CPN_CMDPARSE_TYPE_ACTION,

    /** A simple counter option. Counters do not accept
     * arguments, but may be specified multiple times, causing
     * an integer to be counted up. */
    CPN_CMDPARSE_TYPE_COUNTER,

    /** A public signature key is hex-format. */
    CPN_CMDPARSE_TYPE_SIGKEY,

    /** A simple string argument. */
    CPN_CMDPARSE_TYPE_STRING,

    /** A list of strings. When string lists are used, the user
     * is only allowed to put them at the end of the command
     * line. The string list is initiated by the string list
     * option, leading all following arguments to be added to
     * this list. */
    CPN_CMDPARSE_TYPE_STRINGLIST,

    /** An unsigned integer. */
    CPN_CMDPARSE_TYPE_UINT32,

    /** Each array of `struct cpn_cmdparse_opt` must be
     * terminated by this. */
    CPN_CMDPARSE_TYPE_END
};

#define CPN_CMDPARSE_OPT_ACTION(action, opts, optional) { 0, (action), CPN_CMDPARSE_TYPE_ACTION, {(opts)}, (optional), false }
#define CPN_CMDPARSE_OPT_COUNTER(s, l) { (s), (l), CPN_CMDPARSE_TYPE_COUNTER, {NULL}, true, false }
#define CPN_CMDPARSE_OPT_SIGKEY(s, l, optional) { (s), (l), CPN_CMDPARSE_TYPE_SIGKEY, {NULL}, (optional), false }
#define CPN_CMDPARSE_OPT_STRING(s, l, optional) { (s), (l), CPN_CMDPARSE_TYPE_STRING, {NULL}, (optional), false }
#define CPN_CMDPARSE_OPT_STRINGLIST(s, l, optional) { (s), (l), CPN_CMDPARSE_TYPE_STRINGLIST, {NULL}, (optional), false }
#define CPN_CMDPARSE_OPT_UINT32(s, l, optional) { (s), (l), CPN_CMDPARSE_TYPE_UINT32, {NULL}, (optional), false }
#define CPN_CMDPARSE_OPT_END                    { 0, NULL, CPN_CMDPARSE_TYPE_END, {NULL}, false, false }

/** @brief A simple list of arguments
 *
 * This structure contains a pointer to the first argument of the
 * string list as well as a count of how many arguments are added
 * to the list.
 */
struct cpn_cmdparse_stringlist {
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
 * specified by the enum `cpn_cmdparse_type`. It is only valid to
 * access the value corresponding to the given type.
 *
 * Note that the array of options is always required to be
 * terminated with `CPN_CMDPARSE_OPT_END`.
 */
struct cpn_cmdparse_opt {
    char short_name;
    const char *long_name;
    enum cpn_cmdparse_type type;
    union {
        struct cpn_cmdparse_opt *action_opts;
        uint32_t counter;
        struct cpn_sign_key_public sigkey;
        const char *string;
        struct cpn_cmdparse_stringlist stringlist;
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
int cpn_cmdparse_parse(struct cpn_cmdparse_opt *opts, int argc, const char *argv[]);

#endif

/** @} */
