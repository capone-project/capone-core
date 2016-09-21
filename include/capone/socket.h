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
 * \defgroup cpn-socket Socket
 * \ingroup cpn-lib
 *
 * @brief Module providing networked sockets
 *
 * This module provides functions handling incoming network
 * traffic. One can create a new socket and accept incoming
 * connections.
 *
 * The module provides UDP and TCP sockets.
 *
 * @{
 */

#ifndef CPN_LIB_SOCKET_H
#define CPN_LIB_SOCKET_H

#include "capone/channel.h"

/** @brief Socket struct bundling data for a socket
 *
 * This struct bundles together data required for accepting
 * connections on a socket.
 */
struct cpn_socket {
    /** File descriptor to listen on */
    int fd;
    /** Local address of the socket */
    struct sockaddr_storage addr;
    /** Length of sockaddr struct */
    socklen_t addrlen;
    /** Type of the socket, either UDP or TCP. */
    enum cpn_channel_type type;
};

/** Initialize a socket with host and port
 *
 * Initialize a socket struct to set up a socket listening
 * on the give naddress and port. The socket will be bound, but
 * not be in listening state for the TCP network protocol.
 *
 * @param[out] socket Socket struct to initialize.
 * @param[in] host Host to bind to.
 * @param[in] port Port to bind to.
 * @param[in] type Type of the socket, either UDP or TCP.
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_socket_init(struct cpn_socket *socket,
        const char *host, uint32_t port, enum cpn_channel_type type);

/** Close a socket
 *
 * @param[in] socket Socket to close
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_socket_close(struct cpn_socket *socket);

/** Enable broadcasting on the socket
 *
 * To send messages to the broadcast address, one needs to enable
 * broadcasting for the socket. This function provides the
 * functionality to do so.
 *
 * @param[in] socket Socket to enable broadcasting for.
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_socket_enable_broadcast(struct cpn_socket *socket);

/** Set socket into listening state
 *
 * Set the socket into listening state. This is require
 * for TCP sockets, where one needs to set the socket into
 * listening mode in order to enable accepting connections.
 *
 * @param[in] socket Socket to enable listening for.
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_socket_listen(struct cpn_socket *socket);

/** Accept a new connection
 *
 * Accept a new connection for sockets in listening mode. This
 * will wait for clients to connect to the socket and then create
 * a new channel of the same network mode as the socket.
 * This new channel can then be used to communicate with the
 * connected client.
 *
 * @param[in] socket Socket to accept connections on.
 * @param[out] out Channel connected to the connecting client.
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_socket_accept(struct cpn_socket *socket, struct cpn_channel *out);

/** Get the address of a bound socket
 *
 * Get the address the socket is bound to. It is possible
 * to set retrieve only host or port, but one of both has to be
 * set.
 *
 * @param[in] s socket to get address for.
 * @param[out] host Caller-allocated buffer for the host name.
 *             May be <code>NULL</code> if port is not.
 * @param[in] hostlen Maximum length of the host buffer.
 * @param[out] port Caller-allocated buffer for the port name.
 *             May be <code>NULL</code> if host is not.
 * @return <code>0</code> on success, <code>1</code> otherwise
 */
int cpn_socket_get_address(struct cpn_socket *s,
        char *host, size_t hostlen, uint32_t *port);

#endif

/** @} */
