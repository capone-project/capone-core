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

#include <stdint.h>

#include <sodium/crypto_box.h>

struct schannel {
    int fd;

    uint8_t nonce[crypto_box_NONCEBYTES];
    uint8_t nonce_offset;

    uint8_t pkey[crypto_box_PUBLICKEYBYTES];
    uint8_t skey[crypto_box_SECRETKEYBYTES];
    uint8_t rkey[crypto_box_PUBLICKEYBYTES];
};

int schannel_init(struct schannel *channel, uint8_t *pkey, uint8_t *skey, uint8_t *rkey);
int schannel_close(struct schannel *channel);

int schannel_connect(struct schannel *channel, char *host, uint32_t port);
int schannel_write(struct schannel *c, uint8_t *buf, size_t len);
int schannel_receive(struct schannel *c, void *buf, size_t maxlen);
