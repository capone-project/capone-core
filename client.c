#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include "common.h"

#define PROBE_MESSAGE "PROBE"

static void probe(void *payload)
{
    struct sockaddr_in maddr;
    unsigned int ttl = 1;
    int sock;
    int ret;

    UNUSED(payload);

    memset(&maddr, 0, sizeof(maddr));
    maddr.sin_family = AF_INET;
    maddr.sin_addr.s_addr = inet_addr("224.0.0.1");
    maddr.sin_port = htons(6667);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        printf("Could not open probe socket: %s\n", strerror(errno));
        goto out;
    }

    ret = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    if (ret < 0) {
        printf("Could not set TTL: %s\n", strerror(errno));
        goto out;
    }

    while (true) {
        ret = sendto(sock, PROBE_MESSAGE, strlen(PROBE_MESSAGE), 0,
                (struct sockaddr*)&maddr, sizeof(maddr));
        if (ret < 0) {
            printf("Could not send probe: %s\n", strerror(errno));
            goto out;
        }

        sleep(5);
    }

out:
    if (sock >= 0)
        close(sock);
}

static void receive(void *payload)
{
    struct sockaddr_in laddr;
    int sock, csock, ret;
    char buf[4096];
    ssize_t buflen;

    UNUSED(payload);

    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = htonl(INADDR_ANY);
    laddr.sin_port = htons(6668);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        printf("Could not open receive socket: %s\n", strerror(errno));
        goto out;
    }

    ret = bind(sock, (struct sockaddr*)&laddr, sizeof(laddr));
    if (ret < 0) {
        printf("Could not bind receive socket: %s\n", strerror(errno));
        goto out;
    }

    ret = listen(sock, 1);
    if (ret < 0) {
        printf("Could not listen on receive socket: %s\n", strerror(errno));
        goto out;
    }

    csock = accept(sock, NULL, NULL);
    if (csock < 0) {
        printf("Could not accept announcement: %s\n", strerror(errno));
        goto out;
    }

    buflen = read(csock, buf, sizeof(buf));
    if (buflen < 0) {
        printf("Could not read from announce socket: %s\n", strerror(errno));
        goto out;
    }

    printf("Received %lu bytes announcement: '%s'\n", buflen, buf);

out:
    if (sock >= 0)
        close(sock);
    if (csock >= 0)
        close(csock);
}

int main(int argc, char *argv[])
{
    UNUSED(argc);
    UNUSED(argv);

    int pid, ppid, rpid;

    ppid = spawn(probe, NULL);
    rpid = spawn(receive, NULL);

    while (true) {
        pid = waitpid(-1, NULL, 0);

        if (pid < 0) {
            printf("Could not await child exit: %s\n", strerror(errno));
            return -1;
        } else if (pid == ppid) {
            puts("Probe finished");
        } else if (pid == rpid) {
            puts("Receive finished");
            kill(ppid, SIGTERM);
        } else {
            puts("Unknown child finished");
            return -1;
        }
    }

    return 0;
}
