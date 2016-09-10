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
 * \defgroup cpn-proto Protocols
 * \ingroup cpn-lib
 *
 * @brief Module handling protocols
 *
 * This module provides functions for using the protocols.
 * There currently exist four different protocol end points
 * handled by the server:
 *  - query: Query a service. This will return info like its
 *    type, version, location and available parameters.
 *  - request: Request a new session with a set of parameters.
 *    The session can later be connected to to start it.
 *  - connect: Connect to an already established session and
 *    invoke the associated service to start using its
 *    functionality. This consumes the session.
 *  - terminate: Terminate an established session. This can only
 *    be invoked by the session issuer.
 *
 * @{
 */

#ifndef CPN_LIB_PROTO_H
#define CPN_LIB_PROTO_H

#include "capone/caps.h"
#include "capone/channel.h"
#include "capone/service.h"

/** @brief Connection types specifying the end point
 *
 * These types specify the different protocol end points of a
 * server. They are used to distinguish what to do on the server
 * side and how to handle the incoming request.
 */
enum cpn_command {
    /** @brief Query a service */
    CPN_COMMAND_QUERY,
    /** @brief Connect to an established session */
    CPN_COMMAND_CONNECT,
    /** @brief Request a new session */
    CPN_COMMAND_REQUEST,
    /** @brief Terminate an established session */
    CPN_COMMAND_TERMINATE
};

/** @brief Receive connection type on an established connection
 *
 * This function will receive the client's connection type on an
 * already established and encrypted channel.
 *
 * @param[out] out Connection type requested by the client
 * @param[in] channel Channel connected to the client
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_server_await_command(enum cpn_command *out,
        struct cpn_channel *channel);

/** @brief Await encryption initiated by the client
 *
 * Wait for the client to start the encryption protocol. This
 * will calculate a shared secret with the client.
 *
 * @param[in] channel Channel connected to the client
 * @param[in] sign_keys Local long-term signature keys
 * @param[in] remote_sign_key Remote long-term signature key
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_proto_initiate_encryption
 */
int cpn_server_await_encryption(struct cpn_channel *channel,
        const struct cpn_sign_key_pair *sign_keys,
        struct cpn_sign_key_public *remote_sign_key);

/** @brief Answer a query from a client
 *
 * This function will answer a query received from the client
 * associated with the channel. It will send over parameters
 * specified by the service.
 *
 * @param[in] channel Channel connected to the client
 * @param[in] service Service to send query results for
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_client_query_service
 */
int cpn_server_handle_query(struct cpn_channel *channel,
        const struct cpn_service *service);

/** @brief Handle a session request
 *
 * Handle a session request issued by a client. This function
 * will create a new capability for the invoker specified in the
 * request if the cilent is actually allowed to create sessions
 * on the server.
 *
 * @pram[in] channel Channel connected to the client
 * @param[in] remote_key Long term signature key of the client
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_client_request_session
 */
int cpn_server_handle_request(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key,
        const struct cpn_service_plugin *plugin);

/** @brief Handle incoming session invocation
 *
 * This function will receive an incomming session initiation
 * request and start the service handler when the session
 * initiation and remote identity match a local capability.
 *
 * @param[in] channel Channel connected to the client
 * @param[in] remote_key Long term signature key of the client
 * @param[in] service Service which is being invoked
 * @param[in] cfg Configuration of the server
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_client_start_session
 */
int cpn_server_handle_session(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key,
        const struct cpn_service *service,
        const struct cpn_cfg *cfg);

/** @brief Handle incoming session termination
 *
 * This function handles incoming requests for session
 * termination issued by a client. It will check if a capability
 * is present for the given session identifier and invoker and if
 * so, check if the client's identity matches the capability's
 * issuer.
 *
 * If so, it will remove the capability.
 *
 * @param[in] channel Channel connected to the client
 * @param[in] remote_key Long term signature key of the client
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_client_terminate_session
 */
int cpn_server_handle_termination(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key);

#endif

/** @} */
