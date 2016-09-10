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

#ifndef CAPONE_BUF_H
#define CAPONE_BUF_H

#include <stdlib.h>

struct cpn_buf {
    char *data;
    size_t allocated;
    size_t length;
};

#define CPN_BUF_INIT { NULL, 0, 0 }

/** @brief Set contents of buffer to string
 *
 * Overwrite the current contents of the buffer with the contents
 * of the given string.
 *
 * @param[in] buf Buffer to overwrite
 * @param[in] string String to overwrite with
 */
int cpn_buf_set(struct cpn_buf *buf, const char *string);

/** @brief Append string to current content
 *
 * Append the string to the currently contained string.
 *
 * @param[in] buf Buffer to append
 * @param[in] string String to append
 */
int cpn_buf_append(struct cpn_buf *buf, const char *string);

/** @brief Append string to current content
 *
 * Append the string to the currently contained string.
 *
 * @param[in] buf Buffer to append
 * @param[in] data Data to append
 * @param[in] len Length of data to append
 */
int cpn_buf_append_data(struct cpn_buf *buf, const unsigned char *data, size_t len);

/** @brief Use printf-style formatting to append string
 *
 * Generate the format according to the formatter string and
 * append the results to the buffer.
 *
 * @param[in] buf Buffer to append formatted string to
 * @param[in] format Format to use
 */
int cpn_buf_printf(struct cpn_buf *buf, const char *format, ...);

/** @brief Reset position to beginning
 *
 * Reset the position of the buffer without freeing associated
 * memory. May be utilized to re-use buffers multiple times.
 *
 * @param[in] buf Buffer to reset
 */
void cpn_buf_reset(struct cpn_buf *buf);

/** @brief Clear buffer's contents
 *
 * Clear the buffer, releasing all associated memory.
 *
 * @param[in] buf Buffer to clear
 */
void cpn_buf_clear(struct cpn_buf *buf);

#endif
