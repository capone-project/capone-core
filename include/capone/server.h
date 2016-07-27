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
 * \defgroup sd-server Server
 * \ingroup sd-lib
 *
 * @brief Module providing networked servers
 *
 * This module provides functions handling incoming network
 * traffic. One can create a new server socket and accept
 * incoming connections.
 *
 * The module provides UDP and TCP server sockets.
 *
 * @{
 */

#ifndef CPN_LIB_SERVER_H
#define CPN_LIB_SERVER_H

#include "capone/channel.h"

/** @brief Server struct bundling data for a server socket
 *
 * This struct bundles together data required for accepting
 * connections on a server socket.
 */
struct cpn_server {
    /** File descriptor to listen on */
    int fd;
    /** Local address of the socket */
    struct sockaddr_storage addr;
    /** Type of the socket, either UDP or TCP. */
    enum cpn_channel_type type;
};

/** Initialize a server socket with host and port
 *
 * Initialize a server struct to set up a server socket listening
 * on the give naddress and port. The socket will be bound, but
 * not be in listening state for the TCP network protocol.
 *
 * @param[out] server Server struct to initialize.
 * @param[in] host Host to bind to.
 * @param[in] port Port to bind to.
 * @param[in] type Type of the socket, either UDP or TCP.
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_server_init(struct cpn_server *server,
        const char *host, const char *port, enum cpn_channel_type type);

/** Close a server socket
 *
 * @param[in] server Server to close
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_server_close(struct cpn_server *server);

/** Enable broadcasting on the server socket
 *
 * To send messages to the broadcast address, one needs to enable
 * broadcasting for the socket. This function provides the
 * functionality to do so.
 *
 * @param[in] server Server to enable broadcasting for.
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_server_enable_broadcast(struct cpn_server *server);

/** Set server socket into listening state
 *
 * Set the server socket into listening state. This is require
 * for TCP sockets, where one needs to set the socket into
 * listening mode in order to enable accepting connections.
 *
 * @param[in] server Server to enable listening for.
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_server_listen(struct cpn_server *server);

/** Accept a new connection
 *
 * Accept a new connection for servers in listening mode. This
 * will wait for clients to connect to the socket and then create
 * a new channel of the same network mode as the server socket.
 * This new channel can then be used to communicate with the
 * connected client.
 *
 * @param[in] server Server to accept connections on.
 * @param[out] out Channel connected to the connecting client.
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_server_accept(struct cpn_server *server, struct cpn_channel *out);

/** Get the address of a bound socket
 *
 * Get the address the server socket is bound to. It is possible
 * to set retrieve only host or port, but one of both has to be
 * set.
 *
 * @param[in] s Server to get address for.
 * @param[out] host Caller-allocated buffer for the host name.
 *             May be <code>NULL</code> if port is not.
 * @param[in] hostlen Maximum length of the host buffer.
 * @param[out] port Caller-allocated buffer for the port name.
 *             May be <code>NULL</code> if host is not.
 * @param[in] portlen Maximum length of the port buffer.
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_server_get_address(struct cpn_server *s,
        char *host, size_t hostlen, char *port, size_t portlen);

#endif

/** @} */
