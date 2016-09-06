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

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <string.h>

#include "capone/channel.h"

#include "test.h"

void assert_file_equal(FILE *f, const char *expected)
{
    long size;
    char *data;

    assert_success(fseek(f, 0, SEEK_END));
    size = ftell(f);
    assert_success(fseek(f, 0, SEEK_SET));

    data = malloc(size + 1);
    assert_int_equal(fread(data, size, 1, f), 1);
    data[size] = 0;

    assert_success(fclose(f));

    assert_string_equal(data, expected);

    free(data);
}

int _execute_test_suite(const char *name, const struct CMUnitTest *tests, const size_t count,
        CMFixtureFunction setup, CMFixtureFunction teardown)
{
    printf("[==========] Running testsuite %s\n", name);
    return _cmocka_run_group_tests(name, tests, count, setup, teardown);
}

void stub_sockets(struct cpn_channel *local, struct cpn_channel *remote, enum cpn_channel_type type)
{
    int lfd, rfd;
    struct sockaddr_in addr;
    struct sockaddr_storage laddr, raddr;
    socklen_t laddrlen = sizeof(laddr), raddrlen = sizeof(raddr);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (type == CPN_CHANNEL_TYPE_TCP) {
        int sfd;
        struct sockaddr_storage saddr;
        socklen_t saddrlen = sizeof(saddr);

        assert((sfd = socket(AF_INET, SOCK_STREAM, 0)) >= 0);
        assert_success(bind(sfd, (struct sockaddr * ) &addr, sizeof(addr)));
        assert_success(listen(sfd, 1));
        assert_success(getsockname(sfd, (struct sockaddr *) &saddr, &saddrlen));

        assert((rfd = socket(AF_INET, SOCK_STREAM, 0)) >= 0);
        assert_success(connect(rfd, (struct sockaddr *) &saddr, saddrlen));
        lfd = accept(sfd, NULL, NULL);

        assert_success(close(sfd));
    } else {
        assert((rfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0);
        assert_success(bind(rfd, (struct sockaddr *) &addr, sizeof(addr)));

        assert((lfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0);
        assert_success(bind(lfd, (struct sockaddr *) &addr, sizeof(addr)));
    }

    assert_success(getsockname(lfd, (struct sockaddr *) &laddr, &laddrlen));
    assert_success(getsockname(rfd, (struct sockaddr *) &raddr, &raddrlen));

    assert_success(cpn_channel_init_from_fd(local, lfd, (struct sockaddr *) &raddr, raddrlen, type));
    assert_success(cpn_channel_init_from_fd(remote, rfd, (struct sockaddr *) &laddr, laddrlen, type));
}
