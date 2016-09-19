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

#include <string.h>
#include <stdlib.h>

#include "capone/list.h"

int cpn_list_init(struct cpn_list *list)
{
    struct cpn_list initializer = CPN_LIST_INIT;

    memcpy(list, &initializer, sizeof(struct cpn_list));

    return 0;
}

int cpn_list_append(struct cpn_list *list, void *data)
{
    struct cpn_list_entry *e = malloc(sizeof(struct cpn_list_entry));

    e->data = data;
    e->next = NULL;
    e->prev = list->tail;

    if (list->head == NULL)
        list->head = e;
    if (list->tail)
        list->tail->next = e;
    list->tail = e;

    return 0;
}

int cpn_list_remove(struct cpn_list *list, struct cpn_list_entry *entry)
{
    struct cpn_list_entry *it;

    if (list == NULL || entry == NULL)
        return -1;

    for (it = list->head; it && it != entry; it = it->next);
    if (it == NULL)
        return -1;

    if (entry == list->head)
        list->head = entry->next;
    if (entry == list->tail)
        list->tail = entry->prev;

    if (entry->prev)
        entry->prev->next = entry->next;
    if (entry->next)
        entry->next->prev = entry->prev;

    free(entry);

    return 0;
}

int cpn_list_clear(struct cpn_list *list)
{
    struct cpn_list_entry *e, *next;

    for (e = list->head; e; e = next) {
        next = e->next;
        if (cpn_list_remove(list, e) < 0)
            return -1;
    }

    return 0;
}

struct cpn_list_entry *cpn_list_get(struct cpn_list *list, uint32_t i)
{
    struct cpn_list_entry *it;

    for (it = list->head; i > 0 && it; i--, it = it->next);

    if (i > 0)
        return NULL;

    return it;
}

uint32_t cpn_list_count(const struct cpn_list *list)
{
    uint32_t count = 0;
    struct cpn_list_entry *it;

    if (!list)
        return 0;

    cpn_list_foreach_entry(list, it)
        count++;

    return count;
}
