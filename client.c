#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include "common.h"
#include "log.h"

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
        ret = sendto(sock, PROBE_MESSAGE, strlen(PROBE_MESSAGE), 0,
                (struct sockaddr*)&maddr, sizeof(maddr));
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

static void receive(void *payload)
{
    struct sockaddr_in laddr;
    int sock, ret;
    char buf[4096];
    ssize_t buflen;

    UNUSED(payload);

    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = htonl(INADDR_ANY);
    laddr.sin_port = htons(6668);

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

    buflen = recv(sock, buf, sizeof(buf), 0);
    if (buflen < 0) {
        sd_log(LOG_LEVEL_ERROR, "Could not read announcement package: %s", strerror(errno));
        goto out;
    }

    sd_log(LOG_LEVEL_DEBUG, "Received %lu bytes announcement: '%s'", buflen, buf);

out:
    if (sock >= 0)
        close(sock);
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
