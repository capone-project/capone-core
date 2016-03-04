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
#include "lib/log.h"
#include "lib/service.h"

static const char *version(void)
{
    return "0.0.1";
}

static int parameters(const struct sd_service_parameter **out)
{
    static const struct sd_service_parameter params[] = {
        { "command", 0, NULL },
        { "arg", 0, NULL },
        { "env", 0, NULL },
    };

    *out = params;

    return ARRAY_SIZE(params);
}

static int invoke(struct sd_channel *channel)
{
    if (sd_channel_relay(channel, 1, STDOUT_FILENO) < 0) {
        return -1;
    }

    return 0;
}

static void exec(const char *cmd,
        const char **args, int nargs,
        const char **envs, int nenvs)
{
    char **argv = NULL;
    int i;

    if (nargs > 0) {
        argv = malloc(sizeof(char * const) * nargs + 2);

        argv[0] = strdup(cmd);
        for (i = 0; i < nargs; i++) {
            argv[i + 1] = strdup(args[i]);
        }
        argv[nargs + 1] = NULL;
    }

    for (i = 0; i < nenvs; i++) {
        char *name, *value;

        if (strchr(envs[i], '=') == NULL)
            continue;

        name = strdup(envs[i]);
        value = strchr(name, '=');
        *value = '\0';
        value++;

        setenv(name, value, 0);

        free(name);
    }

    execvp(cmd, argv);

    exit(0);
}

static int handle(struct sd_channel *channel,
        const struct sd_service_parameter *params, size_t nparams)
{
    const char *cmd, **args = NULL, **envs = NULL;
    int pid, nargs, nenvs;
    int stdout_fds[2] = { -1, -1 }, stderr_fds[2] = { -1, -1 };
    int error = 0;

    if (sd_service_parameters_get_value(&cmd, "command", params, nparams) < 0) {
        sd_log(LOG_LEVEL_ERROR, "Missing 'command' parameter");
        return -1;
    }

    nargs = sd_service_parameters_get_values(&args, "arg", params, nparams);
    nenvs = sd_service_parameters_get_values(&envs, "env", params, nparams);

    if ((error = pipe(stdout_fds)) < 0 ||
            (error = pipe(stderr_fds)) < 0)
    {
        sd_log(LOG_LEVEL_ERROR, "Unable to create pipes to child");
        goto out;
    }

    pid = fork();
    if (pid < 0) {
        sd_log(LOG_LEVEL_ERROR, "Unable to fork");
        error = -1;
        goto out;
    }

    if (pid == 0) {
        dup2(stdout_fds[1], STDOUT_FILENO);
        close(stdout_fds[0]);
        close(stdout_fds[1]);
        dup2(stderr_fds[1], STDERR_FILENO);
        close(stderr_fds[0]);
        close(stderr_fds[1]);

        exec(cmd, args, nargs, envs, nenvs);
    } else {
        close(stdout_fds[1]);
        close(stderr_fds[1]);

        if (sd_channel_relay(channel, 2, stdout_fds[0], stderr_fds[0]) < 0) {
            sd_log(LOG_LEVEL_ERROR, "Unable to relay exec output");
            error = -1;
            goto out;
        }
    }

out:
    free(args);
    free(envs);

    if (stdout_fds[0] >= 0) close(stdout_fds[0]);
    if (stdout_fds[1] >= 0) close(stdout_fds[1]);
    if (stderr_fds[0] >= 0) close(stderr_fds[0]);
    if (stderr_fds[1] >= 0) close(stderr_fds[1]);

    return error;
}

int sd_exec_init_service(struct sd_service *service)
{
    service->version = version;
    service->handle = handle;
    service->invoke = invoke;
    service->parameters = parameters;

    return 0;
}
