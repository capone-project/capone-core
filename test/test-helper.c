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
#include <string.h>

#define TEXT1 "abc\ndef\n"
#define TEXT2 "uvw\nxyz\n"

int main(int argc, char *argv[])
{
    if (argc <= 1 || !strcmp(argv[1], "stdout")) {
        fputs(TEXT1, stdout);
        fputs(TEXT2, stdout);
    } else if (!strcmp(argv[1], "mixed")) {
        fputs(TEXT1, stderr);
        fputs(TEXT2, stdout);
    } else if (!strcmp(argv[1], "stderr")) {
        fputs(TEXT1, stderr);
        fputs(TEXT2, stderr);
    }
    return 0;
}
