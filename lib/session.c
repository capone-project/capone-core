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

#include <errno.h>
#include <string.h>

#include <pthread.h>

#include "capone/list.h"
#include "capone/log.h"
#include "capone/service.h"
#include "capone/session.h"

static struct cpn_list sessions;
static uint32_t sessionid;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int cpn_sessions_add(const struct cpn_session **out, ProtobufCMessage *params,
        const struct cpn_sign_key_public *creator)
{
    struct cpn_session *session;

    session = malloc(sizeof(struct cpn_session));
    session->parameters = params;

    if (cpn_cap_create_root(&session->cap) < 0)
        return -1;

    memcpy(&session->creator, creator, sizeof(struct cpn_sign_key_public));

    pthread_mutex_lock(&mutex);
    session->identifier = sessionid++;
    cpn_list_append(&sessions, session);
    pthread_mutex_unlock(&mutex);

    cpn_log(LOG_LEVEL_DEBUG, "Created session %"PRIu32, *out);

    *out = session;

    return 0;
}

int cpn_sessions_remove(struct cpn_session **out, uint32_t sessionid)
{
    struct cpn_list_entry *it;
    struct cpn_session *s;

    pthread_mutex_lock(&mutex);
    cpn_list_foreach(&sessions, it, s) {
        if (s->identifier == sessionid) {
            cpn_list_remove(&sessions, it);
            if (out)
                *out = s;
            else
                cpn_session_free(s);
            break;
        }
    }
    pthread_mutex_unlock(&mutex);

    if (it == NULL) {
        cpn_log(LOG_LEVEL_ERROR, "Session not found");
        return -1;
    }

    return 0;
}

int cpn_sessions_find(const struct cpn_session **out, uint32_t sessionid)
{
    struct cpn_list_entry *it;
    struct cpn_session *s;

    cpn_list_foreach(&sessions, it, s) {
        if (s->identifier == sessionid) {
            if (out)
                *out = s;

            return 0;
        }
    }

    return -1;
}

int cpn_sessions_clear(void)
{
    struct cpn_list_entry *it;
    struct cpn_session *s;

    pthread_mutex_lock(&mutex);

    cpn_list_foreach(&sessions, it, s)
        cpn_session_free(s);
    cpn_list_clear(&sessions);

    pthread_mutex_unlock(&mutex);

    return 0;
}

void cpn_session_free(struct cpn_session *session)
{
    if (session == NULL)
        return;
    cpn_cap_free(session->cap);
    if (session->parameters)
        protobuf_c_message_free_unpacked(session->parameters, NULL);
    free(session);
}
