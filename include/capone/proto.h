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
enum cpn_connection_type {
    /** @brief Query a service */
    CPN_CONNECTION_TYPE_QUERY,
    /** @brief Connect to an established session */
    CPN_CONNECTION_TYPE_CONNECT,
    /** @brief Request a new session */
    CPN_CONNECTION_TYPE_REQUEST,
    /** @brief Terminate an established session */
    CPN_CONNECTION_TYPE_TERMINATE
};

/** @brief Results of a service query
 *
 * This struct represents results of a service query. The include
 * detailed information on the service and parameters that can be
 * set by the client.
 */
struct cpn_query_results {
    /** @brief Name of the service
     * \see cpn_service::name
     */
    char *name;
    /** @brief Category of the service
     * \see cpn_service::category
     */
    char *category;
    /** @brief Type of the service
     * \see cpn_service::type
     */
    char *type;
    /** @brief Version of the service
     * \see cpn_service::version
     */
    char *version;
    /** @brief Location of the service
     * \see cpn_service::location
     */
    char *location;
    /** @brief Port of the service
     * \see cpn_service::port
     */
    char *port;
};

/** @brief Initiate a new connection to a service
 *
 * Initiate a new connection. This includes the following steps:
 *  1. initialize the channel
 *  2. connect to the specified host and port
 *  3. establish an encrypted connection
 *  4. issue the connection type
 *
 * @param[out] channel Channel to initialize and connect
 * @param[in] host Host to connect to
 * @param[in] port Port to connect to
 * @param[in] local_keys Local long-term signature keys
 * @param[in] remote_key Remote long-term signature key
 * @param[in] type Connection type to initialize
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_proto_initiate_connection(struct cpn_channel *channel,
        const char *host,
        const char *port,
        const struct cpn_sign_key_pair *local_keys,
        const struct cpn_sign_key_public *remote_key,
        enum cpn_connection_type type);

/** @brief Receive connection type on an established connection
 *
 * This function will receive the client's connection type on an
 * already established and encrypted channel.
 *
 * @param[out] out Connection type requested by the client
 * @param[in] channel Channel connected to the client
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int cpn_proto_receive_connection_type(enum cpn_connection_type *out,
        struct cpn_channel *channel);

/** @brief Initiate an encrypted connection
 *
 * This function will initiate the encryption protocol on a
 * connected channel. It will invoke the key exchange to generate
 * a new shared secret which while verifying the remote server
 * has knowledge about the secret signature key belonging to the
 * remote public signature key.
 *
 * @param[in] channel Channel connected to the server
 * @param[in] sign_keys Local long-term signature keys
 * @param[in] remote_sign_key Remote long-term signature key
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_proto_await_encryption
 */
int cpn_proto_initiate_encryption(struct cpn_channel *channel,
        const struct cpn_sign_key_pair *sign_keys,
        const struct cpn_sign_key_public *remote_sign_key);

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
int cpn_proto_await_encryption(struct cpn_channel *channel,
        const struct cpn_sign_key_pair *sign_keys,
        struct cpn_sign_key_public *remote_sign_key);

/** @brief Query a remote service for its parameters
 *
 * This function will start the protocol associated with querying
 * the remote service. The channel will have to be initialized
 * with the query connection type.
 *
 * @param[out] out Results sent by the server
 * @param[in] channel Channel connected to the remote server
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_proto_answer_query
 */
int cpn_proto_send_query(struct cpn_query_results *out,
        struct cpn_channel *channel);

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
 * \see cpn_proto_send_query
 */
int cpn_proto_answer_query(struct cpn_channel *channel,
        const struct cpn_service *service);

/** @brief Free query results
 *
 * @param[in] results Results to free
 */
void cpn_query_results_free(struct cpn_query_results *results);

/** @brief Send a session request to the service
 *
 * This function will try to establish a session and capability
 * on the remote server. The session is established for a given
 * invoker which is then able to start the session and a set of
 * parameters.
 *
 * The channel has to be initialized with the request connection
 * type.
 *
 * @param[out] sessionid Identifier for the newly
 *                       established session
 * @param[out] cap Capability used for the session
 * @param[in] channel Channel connected to the server
 * @param[in] params protobuf containing service parameters
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_proto_answer_request
 */
int cpn_proto_send_request(uint32_t *sessionid,
        struct cpn_cap **cap,
        struct cpn_channel *channel,
        const struct ProtobufCMessage *params);

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
 * \see cpn_proto_send_request
 */
int cpn_proto_answer_request(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key,
        const struct cpn_service_plugin *plugin);

/** @brief Start a session
 *
 * Invoke a session that has been previously created on the
 * server. This function will start the local service handler to
 * actually handle its functionality.
 *
 * The channel has to be initialized with the connect connection
 * type.
 *
 * @param[in] channel Channel connected to the server
 * @param[in] sessionid Identifier of the session to be invoked
 * @param[in] cap Capability referencing the session
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_proto_handle_session
 */
int cpn_proto_initiate_session(struct cpn_channel *channel,
        uint32_t sessionid, const struct cpn_cap *cap);

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
 * \see cpn_proto_initiate_session
 */
int cpn_proto_handle_session(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key,
        const struct cpn_service *service,
        const struct cpn_cfg *cfg);

/** @brief Initiate session termination
 *
 * Request the server to terminate a capability which has been
 * created for the given session identifier and invoker. This is
 * only allowed if the capability has been created by the local
 * identity.
 *
 * The channel has to be initialized with the terminate
 * connection type.
 *
 * @param[in] channel Channel connected to the service.
 * @param[in] sessionid Identifier of the session
 * @param[in] cap Capability granting the ability to terminate an
 *            object
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_proto_handle_termination
 */
int cpn_proto_initiate_termination(struct cpn_channel *channel,
        uint32_t sessionid, const struct cpn_cap *cap);

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
 * \see cpn_proto_initiate_termination
 */
int cpn_proto_handle_termination(struct cpn_channel *channel,
        const struct cpn_sign_key_public *remote_key);

#endif

/** @} */
