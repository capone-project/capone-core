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

#ifndef CAPONE_CMDPARSE_H
#define CAPONE_CMDPARSE_H

#include <stdbool.h>
#include <inttypes.h>

#include "capone/keys.h"

enum cpn_cmdparse_type {
    CPN_CMDPARSE_TYPE_ACTION,
    CPN_CMDPARSE_TYPE_SIGKEY,
    CPN_CMDPARSE_TYPE_STRING,
    CPN_CMDPARSE_TYPE_UINT32,
    CPN_CMDPARSE_TYPE_END
};

#define CPN_CMDPARSE_OPT_ACTION(action, opts, optional) { 0, (action), CPN_CMDPARSE_TYPE_ACTION, {(opts)}, (optional), false }
#define CPN_CMDPARSE_OPT_SIGKEY(s, l, optional) { (s), (l), CPN_CMDPARSE_TYPE_SIGKEY, {NULL}, (optional), false }
#define CPN_CMDPARSE_OPT_STRING(s, l, optional) { (s), (l), CPN_CMDPARSE_TYPE_STRING, {NULL}, (optional), false }
#define CPN_CMDPARSE_OPT_UINT32(s, l, optional) { (s), (l), CPN_CMDPARSE_TYPE_UINT32, {NULL}, (optional), false }
#define CPN_CMDPARSE_OPT_END                    { 0, NULL, CPN_CMDPARSE_TYPE_END, {NULL}, false, false }

struct cpn_cmdparse_opt {
    char short_name;
    const char *long_name;
    enum cpn_cmdparse_type type;
    union {
        struct cpn_cmdparse_opt *action_opts;
        struct cpn_sign_key_public sigkey;
        const char *string;
        uint32_t uint32;
    } value;
    bool optional;
    bool set;
};

int cpn_cmdparse_parse(struct cpn_cmdparse_opt *opts, int argc, const char *argv[]);

#endif
