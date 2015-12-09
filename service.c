#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#define ANNOUNCE_MESSAGE "ANNOUNCE"

struct announce_payload {
    struct sockaddr_in addr;
    socklen_t addrlen;
    char *buf;
    size_t buflen;
};

static void announce(void *payload)
{
    struct announce_payload *p = (struct announce_payload *)payload;
    struct sockaddr_in raddr = p->addr;
    int ret, sock;

    printf("Received %lu bytes from %s: '%s'\n", p->buflen,
            inet_ntoa(p->addr.sin_addr), p->buf);

    raddr.sin_port = htons(6668);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        printf("Could not open announce socket: %s\n", strerror(errno));
        goto out;
    }

    ret = sendto(sock, ANNOUNCE_MESSAGE, sizeof(ANNOUNCE_MESSAGE), 0,
            (struct sockaddr*)&raddr, sizeof(raddr));
    if (ret < 0) {
        printf("Unable to send announce: %s\n", strerror(errno));
        goto out;
    }

out:
    if (sock >= 0)
        close(sock);
}

int main(int argc, char *argv[])
{
    struct sockaddr_in maddr, raddr;
    int sock, ret;
    char buf[4096];

    UNUSED(argc);
    UNUSED(argv);

    memset(&maddr, 0, sizeof(maddr));
    maddr.sin_family = AF_INET;
    maddr.sin_addr.s_addr = htonl(INADDR_ANY);
    maddr.sin_port = htons(6667);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        printf("Could not open socket: %s\n", strerror(errno));
        goto out;
    }

    ret = bind(sock, (struct sockaddr*)&maddr, sizeof(maddr));
    if (ret < 0) {
        printf("Could not bind socket: %s\n", strerror(errno));
        goto out;
    }

    while (true) {
        struct announce_payload payload;
        socklen_t addrlen = sizeof(raddr);

        waitpid(-1, NULL, WNOHANG);

        memset(&raddr, 0, addrlen);

        ret = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&raddr, &addrlen);
        if (ret < 0) {
            printf("Could not receive: %s\n", strerror(errno));
            goto out;
        }

        payload.addr = raddr;
        payload.addrlen = addrlen;
        payload.buf = buf;
        payload.buflen = ret;

        if (spawn(announce, &payload) < 0) {
            printf("Could not spawn announcer: %s\n", strerror(errno));
            goto out;
        }
    }

out:
    if (sock >= 0)
        close(sock);

    return 0;
}
