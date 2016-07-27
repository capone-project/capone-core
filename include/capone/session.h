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
 * \defgroup cpn-session Session
 * \ingroup cpn-lib
 *
 * @brief Module handling session management
 *
 * Sessions are used to encapsulate parameters associated with a
 * concrete invocation of a service. Clients may request a
 * session that for a certain service that may be later invoked
 * by the client or another party to start using the service.
 *
 * When requesting a session, the client has to choose parameters
 * associated with the session, which are passed on to the
 * service as soon as the session is started.
 *
 * Furthermore, the session requester has to specify an identity
 * for the invoker. This will most often be the requester
 * himself, but may be another identity when the session should
 * be invoked by someone else.
 *
 * Sessions represent a kind of capability. That is they bundle
 * together a session identifier used to distinguish sessions
 * with an invoker. When a client wants to start a session, it is
 * checked if any capability is present with the session
 * identifier given by the client and his identity. If such a
 * session exists, then the client may invoke it, otherwise he
 * will be refused.
 *
 * Sessions may be revoked by the session issuer. When an
 * identity requests a session for another identity but later
 * decides to revoke the capability, he may do so. As such, the
 * invoker is part of the session in order to keep track of who
 * is able to revoke the session.
 *
 * The session parameters can only be chosen by the session
 * issuer. This is by design so that the invoker is not able to
 * escalate privileges specified by the session's parameters.
 *
 * @{
 */

#ifndef CPN_SESSION_H
#define CPN_SESSION_H

#include <inttypes.h>

#include "capone/keys.h"
#include "capone/parameter.h"

/** @brief A session wrapping identities and parameters */
struct cpn_session {
    /** @brief Session identifier used to distinguish sessions */
    uint32_t sessionid;

    /** @brief Parameters chosen for the session */
    struct cpn_parameter *parameters;
    /** @brief Number of parameters */
    size_t nparameters;
};

/** @brief Initialize sessions
 *
 * Initializes structs required for session management. This
 * should be invoked only once when the main executable is
 * started.
 *
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_sessions_init(void);

/** @brief Add a new session
 *
 * Add a new session for the parameters. This will add a new
 * session to the pool of already established sessions.
 *
 * This function may fail if a session with the same session
 * identifier and invoker has already been specified.
 *
 * @param[out] out The ID of the newly created session.
 * @param[in] params Parameters for the session.
 * @param[in] nparams Number of parameters.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_sessions_add(uint32_t *out,
        const struct cpn_parameter *params,
        size_t nparams);

/** @brief Remove a session
 *
 * Remove a session from the pool of already established
 * sessions.
 *
 * @param[out] out Pointer to store removed session at. May be
 *             <code>NULL</code>.
 * @param[in] identity Session invoker to search for.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_sessions_remove(struct cpn_session *out, uint32_t sessionid);

/** @brief Find a session by identifier
 *
 * Finds a session which matches the given session identifier and
 * the session's invoker.
 *
 * @param[out] out Pointer to store found session at.
 * @param[in] sessionid Session identifier to search for.
 * @return <code>0</code> if the session has been found,
 *         <code>-1</code> otherwise
 */
int cpn_sessions_find(struct cpn_session *out, uint32_t sessionid);

/** @brief Remove all established sessions
 *
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_sessions_clear(void);

/** @brief Free a session
 *
 * Free's storage associated with the session. This primarily
 * includes the session's parameters.
 *
 * @param[in] session Session to free
 */
void cpn_session_free(struct cpn_session *session);

#endif

/** @} */
