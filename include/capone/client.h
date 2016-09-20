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

#ifndef CPN_CLIENT_H
#define CPN_CLIENT_H

#include "capone/caps.h"
#include "capone/channel.h"
#include "capone/keys.h"
#include "capone/list.h"
#include "capone/server.h"

/** @brief Results of a single announce message
 *
 * This struct represents the results sent by a single server in
 * response to a probing discovery message.
 */
struct cpn_discovery_results {
    char *name;
    uint32_t version;
    struct cpn_sign_key_public identity;

    struct {
        char *name;
        char *category;
        char *port;
    } *services;
    uint32_t nservices;
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

/** @brief Send a discovery message to query available services
 *
 * Send a new discovery mesasge to the channel. The list of known
 * keys is used in order to tell available servers if they are
 * known to the client already - if so, these servers will not
 * send a new announcement again.
 *
 * @param[in] channel Channel to send discovery to
 * @param[in] known_keys List of keys already known to the client
 */
int cpn_client_discovery_probe(struct cpn_channel *channel, const struct cpn_list *known_keys);

/** @brief Receive discovery announcement and return results
 *
 * @param[out] out Structure to fill with the announcement. Needs
 *             to be cleared with `cpn_discovery_results_clear`.
 * @param[in] channel Channel to read announcement from.
 */
int cpn_client_discovery_handle_announce(struct cpn_discovery_results *out, struct cpn_channel *channel);

/** @brief Clear discovery results
 *
 * Free all memory associated with the results structure. The
 * structure itself will not be free'd.
 */
void cpn_discovery_results_clear(struct cpn_discovery_results *results);

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
int cpn_client_connect(struct cpn_channel *channel,
        const char *host,
        const char *port,
        const struct cpn_sign_key_pair *local_keys,
        const struct cpn_sign_key_public *remote_key);

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
 * \see cpn_server_handle_query
 */
int cpn_client_query_service(struct cpn_query_results *out,
        struct cpn_channel *channel);

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
 * \see cpn_server_handle_request
 */
int cpn_client_request_session(uint32_t *sessionid,
        struct cpn_cap **cap,
        struct cpn_channel *channel,
        const struct ProtobufCMessage *params);

/** @brief Start a session
 *
 * Invoke a session that has been previously created on the
 * server. This function will start the local service handler to
 * actually handle its functionality.
 *
 * The channel has to be initialized with the connect connection
 * type.
 *
 * @param[out] out Session that was started
 * @param[in] channel Channel connected to the server
 * @param[in] sessionid Identifier of the session to be invoked
 * @param[in] cap Capability referencing the session
 * @param[in] plugin Plugin to handle session
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see cpn_server_handle_session
 */
int cpn_client_start_session(struct cpn_session **out,
        struct cpn_channel *channel,
        uint32_t sessionid,
        const struct cpn_cap *cap,
        const struct cpn_service_plugin *plugin);

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
 * \see cpn_server_handle_termination
 */
int cpn_client_terminate_session(struct cpn_channel *channel,
        uint32_t sessionid, const struct cpn_cap *cap);

#endif
