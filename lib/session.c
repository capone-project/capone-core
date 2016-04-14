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

#include <semaphore.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "lib/log.h"
#include "lib/service.h"

#include "session.h"

#define MAX_SESSIONS 1024

static struct {
    struct sd_session sessions[MAX_SESSIONS];
    char used[MAX_SESSIONS];
} *sessions;

static sem_t semaphore;

int sd_sessions_init(void)
{
    int shmid;

    if (sem_init(&semaphore, 0, 1) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to setup semaphore");
        return -1;
    }

    shmid = shmget(IPC_PRIVATE, sizeof(*sessions), IPC_CREAT | IPC_EXCL | 0600);
    if (shmid < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to initialize shared memory");
        return -1;
    }

    sessions = shmat(shmid, NULL, 0);
    memset(sessions, 0, sizeof(*sessions));

    return 0;
}

int sd_sessions_add(int sessionid,
        const struct sd_sign_key_public *identity,
        struct sd_service_parameter *params,
        size_t nparams)
{
    size_t i;

    sem_wait(&semaphore);

    for (i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions->used[i]) {
            sessions->used[i] = 1;
            break;
        }
    }

    sem_post(&semaphore);

    if (i == MAX_SESSIONS) {
        sd_log(LOG_LEVEL_ERROR, "No session space left");
        return -1;
    }

    sessions->sessions[i].sessionid = sessionid;
    memcpy(sessions->sessions[i].identity.data, identity->data, sizeof(identity->data));
    sessions->sessions[i].parameters = params;
    sessions->sessions[i].nparameters = nparams;

    sd_log(LOG_LEVEL_DEBUG, "Created session %"PRIu32, sessionid);

    return 0;
}

int sd_sessions_remove(struct sd_session *out,
        uint32_t sessionid,
        const struct sd_sign_key_public *identity)
{
    size_t i;

    sem_wait(&semaphore);

    for (i = 0; i < MAX_SESSIONS; i++) {
        struct sd_session *s;

        if (!sessions->used[i])
            continue;

        s = &sessions->sessions[i];
        if (s->sessionid == sessionid &&
                memcmp(s->identity.data, identity->data, sizeof(identity->data)) == 0)
        {
            sessions->used[i] = 0;
            break;
        }
    }

    sem_post(&semaphore);

    if (i == MAX_SESSIONS) {
        sd_log(LOG_LEVEL_ERROR, "Session not found");
        return -1;
    }

    memcpy(out, &sessions->sessions[i], sizeof(*out));
    memset(&sessions->sessions[i], 0, sizeof(sessions->sessions[i]));

    return 0;
}

void sd_session_free(struct sd_session *session)
{
    sd_service_parameters_free(session->parameters, session->nparameters);
}
