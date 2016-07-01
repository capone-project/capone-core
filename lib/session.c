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

#include "lib/log.h"
#include "lib/service.h"

#include "session.h"

#define MAX_SESSIONS 1024

static struct sd_session sessions[MAX_SESSIONS];
static char used[MAX_SESSIONS];
static uint32_t sessionid = 0;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int sd_sessions_init(void)
{
    return 0;
}

int sd_sessions_add(uint32_t *out,
        const struct sd_parameter *params,
        size_t nparams)
{
    uint32_t id;
    size_t i;

    pthread_mutex_lock(&mutex);
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (!used[i]) {
            used[i] = 1;
            break;
        }
    }

    id = sessionid++;
    pthread_mutex_unlock(&mutex);

    if (i == MAX_SESSIONS) {
        sd_log(LOG_LEVEL_ERROR, "No session space left");
        return -1;
    }

    sessions[i].sessionid = id;
    *out = id;

    sessions[i].nparameters = sd_parameters_dup(&sessions[i].parameters,
            params, nparams);

    sd_log(LOG_LEVEL_DEBUG, "Created session %"PRIu32, sessionid);

    return 0;
}

int sd_sessions_remove(struct sd_session *out, uint32_t sessionid)
{
    ssize_t i;

    pthread_mutex_lock(&mutex);

    i = sd_sessions_find(out, sessionid);
    if (i >= 0) {
        memset(&sessions[i], 0, sizeof(struct sd_session));
        used[i] = 0;
    }

    pthread_mutex_unlock(&mutex);

    if (i < 0) {
        sd_log(LOG_LEVEL_ERROR, "Session not found");
        return -1;
    }

    return 0;
}

int sd_sessions_find(struct sd_session *out, uint32_t sessionid)
{
    size_t i;

    for (i = 0; i < MAX_SESSIONS; i++) {
        struct sd_session *s;

        if (!used[i])
            continue;

        s = &sessions[i];
        if (s->sessionid == sessionid) {
            if (out)
                memcpy(out, s, sizeof(struct sd_session));

            return 0;
        }
    }

    return -1;
}

int sd_sessions_clear(void)
{
    size_t i;
    pthread_mutex_lock(&mutex);

    for (i = 0; i < MAX_SESSIONS; i++) {
        if (!used[i])
            continue;

        sd_session_free(&sessions[i]);
    }

    memset(used, 0, sizeof(used));
    memset(sessions, 0, sizeof(sessions));
    pthread_mutex_unlock(&mutex);

    return 0;
}

void sd_session_free(struct sd_session *session)
{
    sd_parameters_free(session->parameters, session->nparameters);
}
