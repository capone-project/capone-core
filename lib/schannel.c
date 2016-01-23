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
#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "schannel.h"

int schannel_init(struct schannel *channel, uint8_t *pkey, uint8_t *skey, uint8_t *rkey)
{
    memset(channel, 0, sizeof(struct schannel));

    channel->fd = -1;
    channel->nonce_offset = 2;

    memcpy(channel->pkey, pkey, sizeof(channel->pkey));
    memcpy(channel->skey, skey, sizeof(channel->skey));
    memcpy(channel->rkey, rkey, sizeof(channel->rkey));

    return 0;
}

int schannel_close(struct schannel *channel)
{
    int ret;

    if (channel->fd < 0) {
        sd_log(LOG_LEVEL_WARNING, "Trying to close inactive schannel");
        return -1;
    }

    ret = close(channel->fd);
    if (ret == 0) {
        channel->fd = -1;
    }

    return ret;
}

int schannel_connect(struct schannel *channel, char *host, uint32_t port)
{
    struct sockaddr_in addr;
    int fd, ret;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not open socket: %s",
                strerror(errno));
        ret = fd;
        goto out;
    }

    ret = connect(fd, (struct sockaddr*) &addr, sizeof(addr));
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not connect socket: %s",
                strerror(errno));
        goto out;
    }

out:
    if (ret < 0 && channel->fd >= 0) {
        close(channel->fd);
    }

    return ret;
}

int schannel_write(struct schannel *c, uint8_t *msg, size_t msglen)
{
    uint8_t plain[4096 + crypto_box_MACBYTES], cipher[4096 + crypto_box_MACBYTES];
    uint8_t *ptr;
    int ret, len;

    if (msglen > sizeof(cipher) - crypto_box_MACBYTES) {
        sd_log(LOG_LEVEL_ERROR, "Message length greater than internal buffer");
        return -1;
    }

    memset(plain, 0, crypto_box_MACBYTES);
    memcpy(plain + crypto_box_MACBYTES, msg, msglen);

    ret = crypto_box_easy(cipher, plain, msglen, c->nonce, c->rkey, c->skey);
    if (ret != 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to encrypt message");
        return ret;
    }
    len = crypto_box_MACBYTES + msglen;
    ptr = cipher;

    while (len > 0) {
        ret = write(c->fd, ptr, len);
        if (ret < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not write to socket: %s",
                    strerror(errno));
            return ret;
        }

        len -= ret;
        ptr += ret;
    }

    /* TODO: increase nonce */

    return 0;
}

int schannel_receive(struct schannel *c, void *buf, size_t maxlen)
{
    uint8_t cipher[4096 + crypto_box_MACBYTES];
    int ret;

    ret = read(c->fd, cipher, sizeof(cipher));
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not read from socket: %s",
                strerror(errno));
        return ret;
    }

    if ((unsigned) ret > maxlen) {
        sd_log(LOG_LEVEL_ERROR, "Could not decipher received text: "
                "Receive buffer too short");
        return -1;
    }

    /* TODO: retrieve nonce */

    ret = crypto_box_open_easy(buf, cipher, ret, NULL, c->rkey, c->skey);
    if (ret != 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not decipher received text");
        return -1;
    }

    return 0;
}
