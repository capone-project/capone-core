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
 * \defgroup sd-cfg Configuration
 * \ingroup sd-lib
 *
 * @brief Module handling parsing of configurations.
 *
 * This module provides functions used for parsing configuration
 * string or files. A configuration file is structured by named
 * sections, where each section conains a number of entries
 * containing the actual values.
 *
 * The configuration file format is similar to the TOML language
 * but somewhat simpler. There are no global sections and each
 * section entry's name and value are always simple strings.
 *
 * The following code is an example for a configuration comprised
 * out of three sections, where the first and third section have
 * entries and the second one is empty.
 *
 * \code{.unparsed}
 * [core]
 * type=test
 *
 * [empty]
 *
 * [section]
 * name1=value
 * name2=value
 * \endcode
 *
 * @{
 */

#ifndef SD_LIB_CFG_H
#define SD_LIB_CFG_H

#include <stdint.h>
#include <stddef.h>

/** @brief An entry representing a single configuration.
 *
 * A configuration section can group together multiple
 * configurations. Each of these configurations is represented by
 * a single entry comprised of a name and an optional value. The
 * name is used to be able to map the value to a specific domain
 * where the value is used for.
 */
struct sd_cfg_entry {
    /** @brief The entry's name */
    char *name;
    /** @brief The entry's value. May be <code>NULL</code> */
    char *value;
};

/** @brief A named section grouping together multiple entries
 *
 * Sections are use to group together multiple entries. Each
 * section has a name required to identify the section itself.
 */
struct sd_cfg_section {
    /** @brief The seciton's name */
    char *name;
    /** @brief The entries contained in the section. May be <code>NULL>/code> */
    struct sd_cfg_entry *entries;
    /** @brief Number of entries contained in the section */
    size_t numentries;
};

/** @brief A complete configuration comprised of multiple sections
 *
 * A configuration represents a file or string containing
 * multiple sections, which themselves contain entries.
 */
struct sd_cfg {
    /** @brief Sections contained in the configuration */
    struct sd_cfg_section *sections;
    /** @brief Number of sections contained in the configuration */
    size_t numsections;
};

/** @brief Parse a configuration file
 * @param[out] c Pointer to an allocated configuration struct.
 * @param[in]  path Path to the file that is to be parsed.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 * */
int sd_cfg_parse(struct sd_cfg *c, const char *path);

/** @brief Parse a configuration string
 * @param[out] c Pointer to an allocated configuration struct.
 * @param[in] ptr A C string containing the configuration.
 * @param[in] len Length of the C string.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int sd_cfg_parse_string(struct sd_cfg *c, const char *ptr, size_t len);

/** @brief Free contents of a configuration struct */
void sd_cfg_free(struct sd_cfg *c);

/** @brief Get named section of a configuration
 *
 * When multiple sections with the same name are present, we
 * return the first section matching the name.
 *
 * @param[in] c Configuration for which to retrieve the section.
 * @param[in] name Name of the section to search for.
 * @return A pointer to the section or <code>NULL</code> if it
 *         was not found.
 */
const struct sd_cfg_section *sd_cfg_get_section(const struct sd_cfg *c, const char *name);

/** @brief Get entry of a section
 *
 * When multiple entries with the same name are present, we
 * return the first entry matching the name.
 *
 * @param[in] s Section for which to retrieve the entry.
 * @param[in] name Name of the entry to search for.
 * @return A pointer to the entry or <code>NULL</code> if it was
 *         not found.
 */
const struct sd_cfg_entry *sd_cfg_get_entry(const struct sd_cfg_section *s, const char *name);

/** @brief Get the value associated with a section and key
 *
 * Retrieve the value of an entry of a specific section. We will
 * return the first matching entry in the first matching section
 * if multiple entries and/or sections are present. The value is
 * newly allocated and must be freed by the caller.
 *
 * @param[in] c Configuration to search for section and entry.
 * @param[in] section The section's name in which to search.
 * @param[in] key The entry's name to search for.
 * @return A newly allocated string containing the value or
 *         <code>NULL</code>.
 */
char *sd_cfg_get_str_value(const struct sd_cfg *c, const char *section, const char *key);

/** @brief Get the integer associated with a section and key
 *
 * Find the value associated with the section an key and parse
 * it into an integer, if possible.
 *
 * @return The value of the entry parsed as integer. If it was
 *         impossible to parse the integer, <code>0</code> is
 *         returned.
 *
 * \see sd_cfg_get_str_value
 */
int sd_cfg_get_int_value(const struct sd_cfg *c, const char *section, const char *key);

#endif

/** @} */
