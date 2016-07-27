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
 * \defgroup cpn-log Logging
 * \ingroup cpn-lib
 *
 * @brief Module providing logging functions
 *
 * This module provides functions to generate log messages
 * depending on a logging level. Currently, only logging to
 * stdout is supported.
 *
 * There exist multiple log levels which are to be used when
 * logging a message. The standard log level is
 * <code>LOG_LEVEL_DEBUG</code>.
 *
 * @{
 */

#ifndef CPN_LIB_LOG_H
#define CPN_LIB_LOG_H

/** @brief Logging level
 *
 * The log levels are layed out in increasing verbosity levels.
 * That is when the log level is set to e.g.
 * <code>LOG_LEVEL_VERBOSE>, all messages with a higher log level
 * will be printed.
 */
enum log_level {
    /** Trace execution, only inteded for developers */
    LOG_LEVEL_TRACE,
    /** Debug messages, only inteded for developers */
    LOG_LEVEL_DEBUG,
    /** Verbose messages, may help users to comprehend a problem */
    LOG_LEVEL_VERBOSE,
    /** Warning messages, when things may not be as expected */
    LOG_LEVEL_WARNING,
    /** Erorr message, when an error occured */
    LOG_LEVEL_ERROR,
    /** Print no messages */
    LOG_LEVEL_NONE
};

/** @brief Log a message
 *
 * Log a new message with the given format and a specific log
 * level. The log level determines when it will be printed. The
 * format specifier are the same as used by the
 * <code>printf</code> family of functions.
 *
 * @param[in] lvl Log level of the message.
 * @param[in] msgformat Format string.
 */
void cpn_log(enum log_level lvl, const char *msgformat, ...);

/** @brief Set log level
 *
 * Set the log level to suppress or show messages with certain
 * levels.
 *
 * @param[in] lvl Log level to set
 */
void cpn_log_set_level(enum log_level lvl);

#endif

/** @} */
