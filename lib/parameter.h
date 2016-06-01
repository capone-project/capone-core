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
 * \defgroup parameter Parameter
 * \ingroup sd-lib
 *
 * @brief Module handling parameters
 *
 * Services are usually guided by a set of parameters to alter
 * their behavior. This module provides function to ease handling
 * of these parameters.
 *
 * @{
 */

#ifndef SD_LIB_PARAMETER_H
#define SD_LIB_PARAMETER_H

#include <stddef.h>

#include "proto/capabilities.pb-c.h"

/** @brief Service parameters
 *
 * Services can have parameters to change the way they function.
 * This struct provides a simple key-value association to set a
 * certain configuration option to a specified value.
 */
struct sd_parameter {
    /** @brief Key of the parameter */
    const char *key;
    /** @brief Value associated with the key */
    const char *value;
};

/** @brief Filter parameters by their keys
 *
 * Allocate a new array of parameters only containing parameters
 * with the given key. The resulting array needs to be freed with
 * <sd_parameters_free>.
 *
 * @param[out] out Pointer to array to be allocated. May be
 *             <code>NULL</code> if no parameters were found.
 * @param[in] key Key to filter parameters by.
 * @param[in] params Array of parameters to filter.
 * @param[in] nparams Number of parameters in the array.
 * @return Number of resulting parameters.
 */
size_t sd_parameters_filter(struct sd_parameter **out, const char *key,
        const struct sd_parameter *params, size_t nparams);

/** Retrieve a value from parameters
 *
 * Search the given parameters for a key and return its value.
 *
 * @param[out] out Pointer to store value at.
 * @param[in] value Key of the value.
 * @param[in] parameters Parameters to search.
 * @param[in] n Parameter count.
 * @return <code>0</code> on success, <code>-1</code> if the
 *         value was not found
 */
int sd_parameters_get_value(const char **out, const char *value, const struct sd_parameter *parameters, size_t n);

/** Retrieve multiple values from parameters
 *
 * Search the given parameters for a key and return all values
 * found for the given parameter. The caller is responsible of
 * freeing the array only, not the values stored inside of it.
 *
 * @param[out] out Pointer to store values at.
 * @param[in] value Key of the value.
 * @param[in] parameters Parameters to search.
 * @param[in] n Parameter count.
 * @return <code>0</code> on success, <code>-1</code> if no
 *         values were found.
 */
int sd_parameters_get_values(const char ***out, const char *value, const struct sd_parameter *parameters, size_t n);

/** Free service parameters array
 *
 * @param[in] params Parameters array to free
 * @param[in] nparams Number of parameters to free
 */
void sd_parameters_free(struct sd_parameter *params, size_t nparams);

#endif

/** @} */
