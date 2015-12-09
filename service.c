#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sodium/crypto_box.h>

#include "common.h"
#include "log.h"

#include "announce.pb-c.h"
#include "probe.pb-c.h"

static uint8_t pk[crypto_box_PUBLICKEYBYTES];
static uint8_t sk[crypto_box_SECRETKEYBYTES];

struct announce_payload {
    struct sockaddr_in addr;
    socklen_t addrlen;
};

static void announce(void *payload)
{
    AnnounceMessage msg = ANNOUNCE_MESSAGE__INIT;
    uint8_t buf[4096];
    struct announce_payload *p = (struct announce_payload *)payload;
    struct sockaddr_in raddr = p->addr;
    int ret, sock;
    size_t len;

    msg.pubkey.len = crypto_box_PUBLICKEYBYTES;
    msg.pubkey.data = pk;
    msg.port = 6667;
    len = announce_message__get_packed_size(&msg);
    if (len > sizeof(buf)) {
        sd_log(LOG_LEVEL_ERROR, "Announce message longer than buffer");
        goto out;
    }
    announce_message__pack(&msg, buf);

    raddr.sin_port = htons(6668);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not open announce socket: %s\n", strerror(errno));
        goto out;
    }

    ret = sendto(sock, buf, len, 0, (struct sockaddr*)&raddr, sizeof(raddr));
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to send announce: %s\n", strerror(errno));
        goto out;
    }

    sd_log(LOG_LEVEL_DEBUG, "Sent announce message to %s:%u",
            inet_ntoa(raddr.sin_addr), ntohs(raddr.sin_port));

out:
    if (sock >= 0)
        close(sock);
}

static void handle_probes(void *payload)
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
        sd_log(LOG_LEVEL_ERROR, "Could not open socket: %s\n", strerror(errno));
        goto out;
    }

    ret = bind(sock, (struct sockaddr*)&maddr, sizeof(maddr));
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not bind socket: %s\n", strerror(errno));
        goto out;
    }

    sd_log(LOG_LEVEL_DEBUG, "Listening for probes on %s:%u",
            inet_ntoa(maddr.sin_addr), ntohs(maddr.sin_port));

    while (true) {
        ProbeMessage *msg;
        struct announce_payload payload;
        socklen_t addrlen = sizeof(raddr);

        waitpid(-1, NULL, WNOHANG);

        memset(&raddr, 0, addrlen);

        ret = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&raddr, &addrlen);
        if (ret < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not receive: %s\n", strerror(errno));
            goto out;
        }

        msg = probe_message__unpack(NULL, ret, buf);
        if (msg == NULL) {
            sd_log(LOG_LEVEL_ERROR, "Could not unpack probe message");
            goto out;
        }

        sd_log(LOG_LEVEL_DEBUG, "Received %lu bytes from %s", ret,
                inet_ntoa(raddr.sin_addr));

        payload.addr = raddr;
        payload.addrlen = addrlen;

        if (spawn(announce, &payload) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not spawn announcer: %s\n", strerror(errno));
            goto out;
        }

        probe_message__free_unpacked(msg, NULL);
    }

out:
    if (sock >= 0)
        close(sock);
}

static void handle_requests(void *payload)
{
    int sock, ret;
    struct sockaddr_in addr;

    UNUSED(payload);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(6667);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not open socket: %s", strerror(errno));
        goto out;
    }

    ret = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not bind socket: %s", strerror(errno));
        goto out;
    }

    while (true) {
        int cfd;

        ret = listen(sock, 0);
        if (ret < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not listen on socket: %s", strerror(errno));
            goto out;
        }

        cfd = accept(sock, NULL, NULL);
        if (cfd < 0) {
            sd_log(LOG_LEVEL_ERROR, "Couldn ot accept connection: %s", strerror(errno));
            goto out;
        }
    }

out:
    if (sock >= 0)
        close(sock);
}

int main(int argc, char *argv[])
{
    int ppid, rpid;

    UNUSED(argc);
    UNUSED(argv);

    crypto_box_keypair(pk, sk);

    ppid = spawn(handle_probes, NULL);
    rpid = spawn(handle_requests, NULL);

    while (true) {
        int pid = waitpid(-1, NULL, 0);

        if (pid < 0) {
            sd_log(LOG_LEVEL_ERROR, "Could not await child exit: %s", strerror(errno));
            return -1;
        } else if (pid == ppid) {
            sd_log(LOG_LEVEL_DEBUG, "Probe handler finished");
        } else if (pid == rpid) {
            sd_log(LOG_LEVEL_DEBUG, "Request handler finished");
        } else {
            sd_log(LOG_LEVEL_DEBUG, "Unknown child finished");
            return -1;
        }
    }

    return 0;
}
