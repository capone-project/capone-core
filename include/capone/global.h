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

#ifndef CPN_LIB_GLOBAL_H
#define CPN_LIB_GLOBAL_H

typedef int (*cpn_global_shutdown_fn)();

/** @brief Initialize global state */
int cpn_global_init(void);

/** @brief Shutdown global state */
int cpn_global_shutdown(void);

/** @brief Register a function to be called on shutdown */
int cpn_global_on_shutdown(cpn_global_shutdown_fn fn);

#endif
