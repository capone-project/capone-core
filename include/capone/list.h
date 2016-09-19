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
 * \defgroup cpn-list Doubly linked list
 * \ingroup cpn-lib
 *
 * @brief Implementation for a doubly linked list
 *
 * @{
 */

#ifndef CAPONE_LIST_H
#define CAPONE_LIST_H

#include <inttypes.h>

/** @brief A single element of the list */
struct cpn_list_entry {
    void *data;

    struct cpn_list_entry *prev;
    struct cpn_list_entry *next;
};

/** @brief A doubly-linked list */
struct cpn_list {
    struct cpn_list_entry *head;
    struct cpn_list_entry *tail;
};

/** @brief Statically initialize a list */
#define CPN_LIST_INIT { NULL, NULL }

/** @brief Initialize a list
 *
 * Initializing a list will overwrite its contents and reset all
 * pointers to `NULL`.
 *
 * @param[in] list List to initialize
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_list_init(struct cpn_list *list);

/** @brief Append an entry to a list
 *
 * Put a new entry at the end of the list.
 *
 * @param[in] list List to append entry to
 * @param[in] data Data entry to put into the element
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_list_append(struct cpn_list *list, void *data);

/** @brief Remove a list entry
 *
 * Remove the list entry of it is contained inside the list. The
 * entry will be freed and cannot be used after successfully
 * removing the entry.
 *
 * Note that the data element is not freed and has to be manually
 * freed by its users.
 *
 * @param[in] list List to remove entry from
 * @param[in] entry Entry to remove. Will be freed
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_list_remove(struct cpn_list *list, struct cpn_list_entry *entry);

/** @brief Clear all list entries
 *
 * Remove all entries from the list, essentially resetting it to
 * its initial state. All entries are freed in the process.
 *
 * Note that data elements are not freed and are require to be
 * manually freed by its users.
 *
 * @param[in] list List to clear
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_list_clear(struct cpn_list *list);

/** @brief Get entry at an index
 *
 * Return the `i`th element of the list. If the list has less
 * than `i` elements, `NULL` is returned.
 *
 * @param[in] list List to search
 * @param[in] i Index of the entry to get
 * @return pointer to the `i`th entry or `NULL`
 */
struct cpn_list_entry *cpn_list_get(struct cpn_list *list, uint32_t i);

/** @brief Get number of list entries */
uint32_t cpn_list_count(const struct cpn_list *list);

#define cpn_list_foreach_entry(l, it) \
    for ((it) = (l)->head; (it); (it) = (it)->next)

#define cpn_list_foreach(l, it, ptr) \
    for ((it) = (l)->head, (ptr) = (it) ? (it)->data : NULL; \
            (it); \
            (it) = (it)->next, (ptr) = (it) ? (it)->data : NULL)

#endif

/* @} */
