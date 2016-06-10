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
 * \defgroup sd-channel Channel
 * \ingroup sd-lib
 *
 * @brief Module handling network connections.
 *
 * This module provides functions for communicating via the
 * network via either TCP or UDP.
 *
 * Channels use a specific format to exchange data with each
 * other. Each batch of data of a specific length is split into
 * fixed-size blocks, where the first block is prefixed by the
 * whole data's length and the last block is padded with zeroes.
 * This allows the receiving side to determine a package's
 * boundary and thus split packages accordingly, which is
 * required for TCP streams.
 *
 * It is possible to use encrypted channels. After a potential
 * key exchange, one can enable encryption and thus have the
 * complete traffic encrypted with the specified key. We use an
 * authenticated encryption, that is all blocks are prefixed with
 * a message authentication code which is used to determine if
 * the message has been tampered with.
 *
 * To guarantee that no message is encrypted twice with the same
 * key and same output, nonces are counted up. Nonces are
 * initially set to <code>0</code> on the client side and
 * <code>1</code> on the server side and from there on
 * incremented by <code>2</code> after a new block has been
 * encrypted and sent or a received block has been decrypted.
 * Thus, there cannot be a collision of nonces, except when the
 * nonces overflow. As they are sufficiently big, though, this
 * will likely never happen.
 *
 * One has to remain careful to not re-use the same key, though,
 * as there would be repeated nonces then. It is thus advisable
 * to create ephemeral session keys which are only used for a
 * single session and then discarded.
 *
 * @{
 */

#ifndef SD_LIB_CHANNEL_H
#define SD_LIB_CHANNEL_H

#include <sys/socket.h>
#include <stdbool.h>

#include <protobuf-c/protobuf-c.h>

#include <sodium/crypto_box.h>

#include "lib/keys.h"

/** @brief Network communication type */
enum sd_channel_type {
    /** Use UDP as underlying network protocol */
    SD_CHANNEL_TYPE_UDP,
    /** Use TCP as underlying network protocol */
    SD_CHANNEL_TYPE_TCP
};

/** @brief Encryption type */
enum sd_channel_crypto {
    /** No encryption is used */
    SD_CHANNEL_CRYPTO_NONE,
    /** Encrypt the channel with a symmetric key */
    SD_CHANNEL_CRYPTO_SYMMETRIC
};

/** @brief Wether to generate the client- or server-side nonce */
enum sd_channel_nonce {
    /** Use a client-side nonce starting at <code>0</code> */
    SD_CHANNEL_NONCE_CLIENT,
    /** Use a server-side nonce starting at <code>1</code> */
    SD_CHANNEL_NONCE_SERVER
};

/** @brief A channel representing a connection to a remote peer
 *
 * A channel bundles together all data required to communicate
 * with a remote peer.
 */
struct sd_channel {
    int fd;
    struct sockaddr_storage addr;
    size_t addrlen;

    size_t blocklen;

    enum sd_channel_type type;
    enum sd_channel_crypto crypto;

    struct sd_symmetric_key key;
    uint8_t remote_nonce[crypto_box_NONCEBYTES];
    uint8_t local_nonce[crypto_box_NONCEBYTES];
};

/** @brief Initialize a channel with a host and port
 *
 * This function initializes a channel to be ready to connect to
 * a given host and port. Initialization contains the lookup of
 * the host and creation of the socket, but the actual connection
 * is not made.
 *
 * If the given channel type corresponds to TCP, one first has to
 * connect the channel in order to be able to send data.
 *
 * @param[out] c Pointer to an allocated channel to initialize.
 * @param[in] host Host to resolve and later connect to.
 * @param[in] port Port to connect to.
 * @param[in] type Specifies the underlying network protocol used
 *            for the channel.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int sd_channel_init_from_host(struct sd_channel *c,
        const char *host, const char *port, enum sd_channel_type type);

/** @brief Initialize a channel from a file descriptor
 *
 * This function initializes a channel from an already existing
 * file descriptor. This can be useful if file descriptors have
 * been acquired from another source, but if one still wants to
 * use the package format or encryption for traffic going through
 * the file descriptor.
 *
 * The address the file descriptor is connected to has to be
 * passed in to be able to use all functionality provided by the
 * channel.
 *
 * @param[out] c Pointer to an allocated channel to initialize.
 * @param[in] fd Open file descriptor to wrap
 * @param[in] addr Address the file descriptor is connected to
 * @param[in] addrlen Length of the address
 * @param[in] type Type of the underlying network protocol the
 *            file descriptor is using.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int sd_channel_init_from_fd(struct sd_channel *c,
        int fd, const struct sockaddr_storage *addr, size_t addrlen,
        enum sd_channel_type type);

/** @brief Set block length used to split messages
 *
 * When sending a message of a certain length, the package may
 * require to be split up into multiple blocks, where each block
 * is of fixed size. This function sets the block length used to
 * determine package boundaries.
 *
 * Pay attention that each block requires to carry some
 * metadata, where the first block carries 4 bytes of total
 * length and each block contains a message authentication code
 * of 20 bytes. As such, the minimum block length is 21. The
 * maximum block length is fixed at 4096 bytes.
 *
 * @param[in] c Channel to set block length for
 * @param[in] len Length of a single block
 * @return <code>0</code> on success, <code>t1</code> otherwise
 */
int sd_channel_set_blocklen(struct sd_channel *c, size_t len);

/** @brief Close the file descriptor of the channel
 *
 * Close the file descriptor such that the channel cannot be used
 * anymore for communicating with the remote party.
 *
 * @param[in] c Channel whose file descriptor should be closed.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int sd_channel_close(struct sd_channel *c);

/** @brief Check if a channel is closed
 *
 * Check if a channel is closed. Note that this may be unreliable
 * depending on the host's platform.
 *
 * @param[in] c Channel to check
 * @return <code>true</code> if the chanenl is closed,
 *         <code>false</code> otherwise
 */
bool sd_channel_is_closed(struct sd_channel *c);

/** @brief Disable encryption for a channel
 *
 * Disable encryption and return to use plain-text messages
 * again. This zeroes out the channel's symmetric key used for
 * encryption.
 *
 * @param[in] c Channel to disable encryption for.
 * @return <code>0</code>
 */
int sd_channel_disable_encryption(struct sd_channel *c);

/** @brief Enable encryption for a channel
 *
 * Enable encryption for a channel with a given shared secret.
 * The shared secret will subsequently be used to encrypt
 * outgoing messages and decrypt incoming messages.
 *
 * Depending on wether the channel is client-side or server-side,
 * nonces are initialized to start at <code>0</code> on the
 * client side and at <code>1</code> on the server side. It is
 * thus important to get the nonce right, as otherwise messages
 * sent and received cannot be handled correctly.
 *
 * @param[out] c Channel to enable encryption for.
 * @param[in] key Shared key to use for encryption.
 * @param[in] nonce Wether the local nonce is the client-side
 *            nonce or the server-side nonce.
 * @return <code>0</code>
 */
int sd_channel_enable_encryption(struct sd_channel *c,
        const struct sd_symmetric_key *key, enum sd_channel_nonce nonce);

/** @brief Connect a channel
 *
 * Connect the channel with the initialized data. Note that this
 * is only possible for channels whose type is set to TCP, as UDP
 * is a connection-less protocol.
 *
 * @param[out] c Channel to connect
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int sd_channel_connect(struct sd_channel *c);

/** @brief Write data to the channel
 *
 * Write data to the channel connected to a remote party. When
 * writing data, it automatically uses encryption when the
 * channel is set to encrypted mode.
 *
 * @param[in] c Channel to send data on.
 * @param[in] buf Data to send.
 * @param[in] len Length of data to send.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int sd_channel_write_data(struct sd_channel *c, uint8_t *buf, uint32_t len);

/** @brief Receive data from the chanenl
 *
 * Receive data on a channel connected to a remote party.
 * Received data is automatically decrypted for encrypted
 * channels.
 *
 * Data received is always split at the boundaries. That is the
 * initial block's length is inspected and all blocks are
 * received and written to the out buffer until the complete data
 * has been received.
 *
 * @param[in] c Channel to receive data on.
 * @param[out] buf Buffer to write data to.
 * @param[in] maxlen Maximum length of the buffer.
 * @return Length of the received data or <code>-1</code> on
 *         error
 */
ssize_t sd_channel_receive_data(struct sd_channel *c, uint8_t *buf, size_t maxlen);

/** @brief Write a protocol buffer to the channel
 *
 * Write the serialized representation of a protocol buffer
 * message to the channel. All semantics are the same as for
 * writing normal data.
 *
 * @param[in] c Channel to write data to.
 * @param[in] msg Protobuf message to serialize and write.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see sd_channel_write_data
 */
int sd_channel_write_protobuf(struct sd_channel *c, ProtobufCMessage *msg);

/** @brief Receive a protocol buffer from the channel
 *
 * Receive a serialized protocol buffer message and deserialize
 * it according to the message's descriptor. All semantics are
 * the same as for receiving normal data.
 *
 * The received protobuf message will be newly allocated and
 * needs to be freed by the caller by calling the protobuf
 * message's <code>__free_unpacked</code> function.
 *
 * @param[in] c Channel to receive protobuf message on.
 * @param[in] descr Descriptor of the protobuf message.
 * @param[out] msg Location where to store the newly allocated,
 *             deserialized protobuf message.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 *
 * \see sd_channel_receive_data
 */
int sd_channel_receive_protobuf(struct sd_channel *c, const ProtobufCMessageDescriptor *descr, ProtobufCMessage **msg);

/** @brief Relay data between a channel and file descriptors
 *
 * When receiving data on a common file descriptor one commonly
 * needs to relay the data to the remote side, e.g. when
 * implementing special services communicating via file
 * descriptors. To not simply forward data without encryption and
 * authentication, one can instead use this function to relay the
 * file descriptor's data via a channel and thus get encrypted
 * traffic.
 *
 * One can specify multiple file descriptors to relay. All data
 * received on the file descriptors will be sent via the channel.
 * Data received on the channel will be written to the first file
 * descriptor specified.
 *
 * @param[in] c Channel to relay data to/from.
 * @param[in] nfds Number of file descriptors following.
 * @param[in] fds File descriptors to relay data to/from. Only
 *            the first file descriptor will be written to when
 *            receiving data from the channel.
 * @return <code>0</code> on success, <code>-1</code> otherwise
 */
int sd_channel_relay(struct sd_channel *c, int nfds, ...);

#endif

/** @} */
