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

#include <string.h>
#include <unistd.h>

#include "exec.h"

#include "lib/common.h"
#include "lib/channel.h"
#include "lib/service.h"

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct sd_service_parameter **out)
{
    static const struct sd_service_parameter params[] = {
        { "command", 0, NULL },
        { "args", 0, NULL },
    };

    *out = params;

    return ARRAY_SIZE(params);
}

static int handle(struct sd_channel *channel,
        struct sd_service_parameter **params, size_t nparams)
{
    char *cmd, *args[] = { NULL };
    size_t i;
    int pid, fds[2];

    for (i = 0; i < nparams; i++) {
        struct sd_service_parameter *param = params[i];

        /* TODO: proper validation of params */
        if (!strcmp(param->name, "command")) {
            cmd = (char *) param->name;
        }
    }

    if (cmd == NULL) {
        puts("Unable to handle command");
        return -1;
    }

    if (pipe(fds) < 0) {
        puts("Unable to create pipe to child");
        return -1;
    }

    pid = fork();
    if (pid == 0) {
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        close(fds[1]);

        execvp("ls", args);
    } else if (pid > 0) {
        uint8_t buf[4096];
        int ret;

        close(fds[1]);

        while ((ret = read(fds[0], buf, sizeof(buf))) > 0) {
            sd_channel_write_data(channel, buf, ret);
        }
    } else {
        return -1;
    }

    return 0;
}

int sd_exec_init_service(struct sd_service *service)
{
    service->version = version;
    service->status = NULL;
    service->handle = handle;
    service->parameters = parameters;

    return 0;
}
