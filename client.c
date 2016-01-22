#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include <sodium/crypto_box.h>
#include <sodium/crypto_auth.h>

#include "common.h"
#include "log.h"

#include "announce.pb-c.h"
#include "discover.pb-c.h"

#define LISTEN_PORT 6668

static uint8_t pk[crypto_box_PUBLICKEYBYTES];
static uint8_t sk[crypto_box_SECRETKEYBYTES];

static uint8_t rpk[crypto_box_PUBLICKEYBYTES];

static void probe(void *payload)
{
    DiscoverEnvelope env = DISCOVER_ENVELOPE__INIT;
    DiscoverMessage msg = DISCOVER_MESSAGE__INIT;
    uint8_t envbuf[4096], msgbuf[4096], mac[crypto_auth_BYTES];
    struct sockaddr_in maddr;
    unsigned int ttl = 1;
    int sock, ret;
    size_t len;

    UNUSED(payload);

    msg.version = VERSION;
    msg.port = LISTEN_PORT;
    msg.pubkey.len = crypto_box_PUBLICKEYBYTES;
    msg.pubkey.data = pk;
    len = discover_message__get_packed_size(&msg);
    if (len > sizeof(msgbuf)) {
        sd_log(LOG_LEVEL_ERROR, "Discover message longer than buffer");
        goto out;
    }
    discover_message__pack(&msg, msgbuf);

    if (crypto_auth(mac, msgbuf, len, pk) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to sign message");
        goto out;
    }

    env.encrypted = false;
    env.mac.len = crypto_auth_BYTES;
    env.mac.data = mac;
    env.discover.data = msgbuf;
    env.discover.len = len;
    len = discover_envelope__get_packed_size(&env);
    if (len > sizeof(envbuf)) {
        sd_log(LOG_LEVEL_ERROR, "Discover envelope longer than buffer");
        goto out;
    }
    discover_envelope__pack(&env, envbuf);

    memset(&maddr, 0, sizeof(maddr));
    maddr.sin_family = AF_INET;
    maddr.sin_addr.s_addr = inet_addr("224.0.0.1");
    maddr.sin_port = htons(6667);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not open probe socket: %s",
                strerror(errno));
        goto out;
    }

    ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not set TTL: %s", strerror(errno));
        goto out;
    }

    while (true) {
        ret = sendto(sock, envbuf, len, 0, (struct sockaddr*)&maddr, sizeof(maddr));
        if (ret < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not send probe: %s", strerror(errno));
            goto out;
        }

        sleep(5);
    }

out:
    if (sock >= 0)
        close(sock);
}

static void handle_announce(void *payload)
{
    AnnounceEnvelope *env = NULL;
    AnnounceMessage *msg = NULL;
    struct sockaddr_in laddr, raddr;
    int sock, ret;
    uint8_t buf[4096];
    ssize_t buflen;
    socklen_t addrlen;

    UNUSED(payload);

    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = htonl(INADDR_ANY);
    laddr.sin_port = htons(LISTEN_PORT);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not open receive socket: %s", strerror(errno));
        goto out;
    }

    ret = bind(sock, (struct sockaddr*)&laddr, sizeof(laddr));
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not bind receive socket: %s", strerror(errno));
        goto out;
    }

    buflen = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&raddr, &addrlen);
    if (buflen < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not read announcement package: %s", strerror(errno));
        goto out;
    }

    env = announce_envelope__unpack(NULL, buflen, buf);
    if (env == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Could not unpack announce envelope");
        goto out;
    }

    msg = announce_message__unpack(NULL, env->announce.len, env->announce.data);
    if (msg == NULL) {
        sd_log(LOG_LEVEL_ERROR, "Could not unpack announce message");
        goto out;
    }

    if (msg->pubkey.len != sizeof(rpk)) {
        sd_log(LOG_LEVEL_ERROR, "Unexpected key size in announcement");
        goto out;
    }

    if (crypto_auth_verify(env->mac.data, env->announce.data, env->announce.len, msg->pubkey.data) != 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not verify MAC");
        goto out;
    }

    memcpy(rpk, msg->pubkey.data, sizeof(rpk));

    sd_log(LOG_LEVEL_DEBUG, "Successfully retrieved remote public key from server (version %s)",
            msg->version);

out:
    announce_message__free_unpacked(msg, NULL);
    announce_envelope__free_unpacked(env, NULL);
    if (sock >= 0)
        close(sock);
}

int main(int argc, char *argv[])
{
    int pid, ppid, rpid;

    UNUSED(argc);
    UNUSED(argv);

    crypto_box_keypair(pk, sk);

    rpid = spawn(handle_announce, NULL);
    ppid = spawn(probe, NULL);

    while (true) {
        pid = waitpid(-1, NULL, 0);

        if (pid < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not await child exit: %s", strerror(errno));
            return -1;
        } else if (pid == ppid) {
            sd_log(LOG_LEVEL_DEBUG, "Probe finished");
        } else if (pid == rpid) {
            sd_log(LOG_LEVEL_DEBUG, "Receive finished");
            kill(ppid, SIGTERM);
        } else {
            sd_log(LOG_LEVEL_DEBUG, "Unknown child finished");
            return -1;
        }
    }

    return 0;
}
