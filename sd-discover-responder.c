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
#include <stdbool.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sodium/crypto_auth.h>
#include <sodium/crypto_box.h>

#include "common.h"
#include "log.h"

#include "announce.pb-c.h"
#include "discover.pb-c.h"

static uint8_t pk[crypto_box_PUBLICKEYBYTES];
static uint8_t sk[crypto_box_SECRETKEYBYTES];

#define LISTEN_PORT 6667

struct announce_payload {
    struct sockaddr_in addr;
    socklen_t addrlen;
    uint32_t port;
};

static void announce(void *payload)
{
    AnnounceEnvelope env = ANNOUNCE_ENVELOPE__INIT;
    AnnounceMessage msg = ANNOUNCE_MESSAGE__INIT;
    uint8_t msgbuf[4096], envbuf[4096], mac[crypto_auth_BYTES];
    struct announce_payload *p = (struct announce_payload *)payload;
    struct sockaddr_in raddr = p->addr;
    int ret, sock;
    size_t len;

    msg.version = VERSION;
    msg.port = LISTEN_PORT;
    msg.pubkey.len = crypto_box_PUBLICKEYBYTES;
    msg.pubkey.data = pk;
    len = announce_message__get_packed_size(&msg);
    if (len > sizeof(msgbuf)) {
        sd_log(LOG_LEVEL_ERROR, "Announce message longer than buffer");
        goto out;
    }
    announce_message__pack(&msg, msgbuf);

    crypto_auth(mac, msgbuf, len, pk);

    env.announce.data = msgbuf;
    env.announce.len = len;
    env.mac.data = mac;
    env.mac.len = crypto_auth_BYTES;
    len = announce_envelope__get_packed_size(&env);
    if (len > sizeof(envbuf)) {
        sd_log(LOG_LEVEL_ERROR, "Announce envelope longer than buffer");
        goto out;
    }
    announce_envelope__pack(&env, envbuf);

    raddr.sin_port = htons(p->port);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not open announce socket: %s", strerror(errno));
        goto out;
    }

    ret = sendto(sock, envbuf, len, 0, (struct sockaddr*)&raddr, sizeof(raddr));
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send announce: %s", strerror(errno));
        goto out;
    }

    sd_log(LOG_LEVEL_DEBUG, "Sent announce message to %s:%u",
            inet_ntoa(raddr.sin_addr), ntohs(raddr.sin_port));

out:
    if (sock >= 0)
        close(sock);
}

static void handle_discover(void *payload)
{
    struct sockaddr_in maddr, raddr;
    int sock, ret;
    uint8_t buf[4096];

    UNUSED(payload);

    memset(&maddr, 0, sizeof(maddr));
    maddr.sin_family = AF_INET;
    maddr.sin_addr.s_addr = htonl(INADDR_ANY);
    maddr.sin_port = htons(6667);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not open socket: %s", strerror(errno));
        goto out;
    }

    ret = bind(sock, (struct sockaddr*)&maddr, sizeof(maddr));
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not bind socket: %s", strerror(errno));
        goto out;
    }

    sd_log(LOG_LEVEL_DEBUG, "Listening for probes on %s:%u",
            inet_ntoa(maddr.sin_addr), ntohs(maddr.sin_port));

    while (true) {
        DiscoverEnvelope *env;
        DiscoverMessage *msg;
        struct announce_payload payload;
        socklen_t addrlen = sizeof(raddr);

        waitpid(-1, NULL, WNOHANG);

        memset(&raddr, 0, addrlen);

        ret = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&raddr, &addrlen);
        if (ret < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not receive: %s", strerror(errno));
            goto out;
        }

        env = discover_envelope__unpack(NULL, ret, buf);
        if (env == NULL) {
            sd_log(LOG_LEVEL_ERROR, "Could not unpack discover envelope");
            goto out;
        }

        if (env->encrypted) {
            sd_log(LOG_LEVEL_ERROR, "Encrypted discover message not yet supported");
            goto out;
        }

        msg = discover_message__unpack(NULL, env->discover.len, env->discover.data);
        if (msg == NULL) {
            sd_log(LOG_LEVEL_ERROR, "Could not unpack discover message");
            goto out;
        }

        if (crypto_auth_verify(env->mac.data, env->discover.data, env->discover.len, msg->pubkey.data) != 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not verify MAC");
            goto out;
        }

        sd_log(LOG_LEVEL_DEBUG, "Received %lu bytes from %s (version %s)", ret,
                inet_ntoa(raddr.sin_addr), msg->version);

        payload.addr = raddr;
        payload.addrlen = addrlen;
        payload.port = msg->port;

        if (spawn(announce, &payload) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not spawn announcer: %s", strerror(errno));
            goto out;
        }

        discover_message__free_unpacked(msg, NULL);
        discover_envelope__free_unpacked(env, NULL);
    }

out:
    if (sock >= 0)
        close(sock);
}

int main(int argc, char *argv[])
{
    int dpid;

    UNUSED(argc);
    UNUSED(argv);

    crypto_box_keypair(pk, sk);

    dpid = spawn(handle_discover, NULL);

    while (true) {
        int pid = waitpid(-1, NULL, 0);

        if (pid < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not await child exit: %s", strerror(errno));
            return -1;
        } else if (pid == dpid) {
            sd_log(LOG_LEVEL_DEBUG, "Probe handler finished");
        } else {
            sd_log(LOG_LEVEL_DEBUG, "Unknown child finished");
            return -1;
        }
    }

    return 0;
}
