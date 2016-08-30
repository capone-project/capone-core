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

#include "capone/caps.h"
#include "capone/opts.h"

static int parse_rights(uint32_t *out, const char *rights)
{
    uint32_t parsed = 0;

    while (*rights != '\0') {
        switch (*rights) {
            case 'x':
                parsed |= CPN_CAP_RIGHT_EXEC;
                break;
            case 't':
                parsed |= CPN_CAP_RIGHT_TERM;
                break;
            default:
                return -1;
        }
        rights++;
    }

    if (parsed == 0)
        return -1;

    *out = parsed;
    return 0;
}

int main(int argc, const char *argv[])
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING('c', "--capability", "Root capability to dervice from", "CAP", false),
        CPN_OPTS_OPT_SIGKEY('i', "--identity", "Identity to derive new capability for", "IDENTITY", false),
        CPN_OPTS_OPT_STRING('r', "--rights", "Rights to include in the derived capability", "[r|t]+", false),
        CPN_OPTS_OPT_END
    };
    struct cpn_cap *root = NULL, *derived = NULL;
    char *string = NULL;
    int err = -1;
    uint32_t rights;

    if (cpn_opts_parse_cmd(opts, argc, argv) < 0)
        return -1;

    if (cpn_cap_from_string(&root, cpn_opts_get(opts, 'c', NULL)->string) < 0) {
        fprintf(stderr, "Invalid capability '%s'\n", cpn_opts_get(opts, 'c', NULL)->string);
        goto out;
    }

    if (parse_rights(&rights, cpn_opts_get(opts, 'r', NULL)->string) < 0) {
        fprintf(stderr, "Invalid rights '%s'\n", cpn_opts_get(opts, 'r', NULL)->string);
        goto out;
    }

    if (cpn_cap_create_ref(&derived, root, rights, &cpn_opts_get(opts, 'i', NULL)->sigkey) < 0) {
        fputs("Could not create derived reference", stderr);
        goto out;
    }

    if (cpn_cap_to_string(&string, derived) < 0) {
        fputs("Could not unmarshall derived capability", stderr);
    }

    puts(string);

    err = 0;

out:
    cpn_cap_free(root);
    cpn_cap_free(derived);
    free(string);

    return err;
}
