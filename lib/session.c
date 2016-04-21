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

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int sd_sessions_init(void)
{
    return 0;
}

int sd_sessions_add(uint32_t sessionid,
        const struct sd_sign_key_public *identity,
        const struct sd_service_parameter *params,
        size_t nparams)
{
    size_t i, n;

    pthread_mutex_lock(&mutex);

    for (i = 0; i < MAX_SESSIONS; i++) {
        struct sd_session *session = &sessions[i];

        if (!used[i])
            continue;

        if (session->sessionid == sessionid &&
                memcmp(&session->identity, identity, sizeof(*identity)) == 0)
        {
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }

    for (i = 0; i < MAX_SESSIONS; i++) {
        if (!used[i]) {
            used[i] = 1;
            break;
        }
    }

    pthread_mutex_unlock(&mutex);

    if (i == MAX_SESSIONS) {
        sd_log(LOG_LEVEL_ERROR, "No session space left");
        return -1;
    }

    sessions[i].sessionid = sessionid;
    memcpy(sessions[i].identity.data, identity->data, sizeof(identity->data));

    if (nparams) {
        sessions[i].parameters = malloc(nparams * sizeof(params));
        for (n = 0; n < nparams; n++) {
            sessions[i].parameters[n].key = strdup(params[n].key);
            sessions[i].parameters[n].value = strdup(params[n].value);
        }
        sessions[i].nparameters = nparams;
    } else {
        sessions[i].parameters = NULL;
        sessions[i].nparameters = 0;
    }

    sd_log(LOG_LEVEL_DEBUG, "Created session %"PRIu32, sessionid);

    return 0;
}

int sd_sessions_remove(struct sd_session *out,
        uint32_t sessionid,
        const struct sd_sign_key_public *identity)
{
    size_t i;

    pthread_mutex_lock(&mutex);

    for (i = 0; i < MAX_SESSIONS; i++) {
        struct sd_session *s;

        if (!used[i])
            continue;

        s = &sessions[i];
        if (s->sessionid == sessionid &&
                memcmp(s->identity.data, identity->data, sizeof(identity->data)) == 0)
        {
            memcpy(out, &sessions[i], sizeof(*out));
            memset(&sessions[i], 0, sizeof(sessions[i]));

            used[i] = 0;
            break;
        }
    }

    pthread_mutex_unlock(&mutex);

    if (i == MAX_SESSIONS) {
        sd_log(LOG_LEVEL_ERROR, "Session not found");
        return -1;
    }

    return 0;
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
    sd_service_parameters_free(session->parameters, session->nparameters);
}
