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
 * \defgroup sd-common Common
 * \ingroup sd-lib
 *
 * @brief Module for commonly used functions
 *
 * This module provides functions commonly required but with no
 * actual grouping.
 *
 * @{
 */

#ifndef SD_LIB_COMMON_H
#define SD_LIB_COMMON_H

#include <inttypes.h>
#include <pthread.h>

/** @brief calculate the maximum of two values
 *
 * @param[in] a, b Values to calculate maximum for
 * @return Either a or b, depending on which one is greater than
 *         the other
 */
#define MAX(a, b) ((a) >= (b) ? (a) : (b))

/** @brief calculate the minumum of two values
 *
 * @param[in] a, b Values to calculate minumum for
 * @return Either a or b, depending on which one is lesser than
 *         the other
 */
#define MIN(a, b) ((a) > (b) ? (b) : (a))

/** @brief Mark the argument as unused code */
#define UNUSED(x) (void)(x)
/** @brief Calculate an array's size */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/** @brief Prototype for spawned functions */
typedef void *(*thread_fn)(void *);

/** @brief A struct representing another thread
 *
 * When spawning new threads, one often needs to keep track of
 * the spawned threads in order to synchronize or abort them.
 * This struct abstracts the interna and provides an opaque
 * representation of a thread.
 */
struct sd_thread {
    pthread_t t;
};

/** @brief Spawn a new thread
 *
 * Spawn a new thread, invoking the given function with an
 * optional payload for use in the spawned function. Pay
 * attention that the payload needs to be available as long as
 * the function is running, otherwise the spawned thread will
 * dereference invalid data.
 *
 * @param[out] t Thread handle that is being spawned. May be
 *             <code>NULL</code>.
 * @param[in] fn Function to spawn.
 * @param[in] payload Payload that is passed to the function.
 * @return <code>0</code> on success, <code>-1</code> otherwise.
 */
int sd_spawn(struct sd_thread *t, thread_fn fn, void *payload);

/** @brief Kill a spawned thread
 *
 * Kill a thread represented by the thread handle. Killing the
 * thread will abort the function currently running.
 *
 * @param[in] t Thread to kill.
 * @return <code>0</code> on success, <code>-1</code> otherwise.
 *         Note that trying to kill a thread that is not running
 *         does not result in an error.
 */
int sd_kill(struct sd_thread *t);

/** @brief Synchronize with a spawned thread
 *
 * Synchronize with a thread that has been spawned, optionally
 * receiving the value returned by the function. The caller will
 * wait until the thread has terminated.
 *
 * @param[in] t Thread to wait for.
 * @param[out] out Pointer to a location where the value returned
 *             by the thread should be stored at. The value may
 *             need to be freed when the thread did allocate it
 *             on the heap. May be <code>NULL</code>.
 * @return <code>0</code> on success, <code>-1</code> otherwise.
 */
int sd_join(struct sd_thread *t, void **out);

/** @brief Parse a string into an unsigned integer
 *
 * Parse a decimal string into an unsigned integer. This function
 * handles all error cases and thus provides a more readily
 * usable interface than <code>strtol</code>. The function is
 * more strict, as only numbers are allowed and overflows are
 * handled correctly.
 *
 * @param[out] out Where the value should be stored.
 * @param[in] num Number to parse.
 * @return <code>0</code> on success, <code>-1</code> otherwise.
 */
int parse_uint32t(uint32_t *out, const char *num);

#endif

/** @} */
