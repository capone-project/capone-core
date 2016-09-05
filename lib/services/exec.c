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
#include <string.h>
#include <unistd.h>

#include "capone/common.h"
#include "capone/channel.h"
#include "capone/log.h"
#include "capone/opts.h"
#include "capone/service.h"

#include "capone/services/exec.h"
#include "capone/proto/exec.pb-c.h"

static int invoke(struct cpn_channel *channel,
        int argc, const char **argv, const struct cpn_cfg *cfg)
{
    UNUSED(argc);
    UNUSED(argv);
    UNUSED(cfg);

    if (cpn_channel_relay(channel, 1, STDOUT_FILENO) < 0) {
        return -1;
    }

    return 0;
}

static int exec(const char *cmd, const char **args, int nargs)
{
    char **argv = NULL;
    int i, err;

    if (nargs > 0) {
        argv = malloc(sizeof(char * const) * (nargs + 2));

        argv[0] = strdup(cmd);
        for (i = 0; i < nargs; i++) {
            argv[i + 1] = strdup(args[i]);
        }
        argv[nargs + 1] = NULL;
    } else {
        argv = malloc(sizeof(char * const) * 2);
        argv[0] = strdup(cmd);
        argv[1] = NULL;
    }

    if ((err = execvp(cmd, argv)) < 0)
        cpn_log(LOG_LEVEL_ERROR, "Could not spawn %s: %s", cmd, strerror(errno));

    for (i = 0; i < nargs; i++) {
        free(argv[i]);
    }
    free(argv);

    return err;
}

static int handle(struct cpn_channel *channel,
        const struct cpn_sign_key_public *invoker,
        const struct cpn_session *session,
        const struct cpn_cfg *cfg)
{
    ExecParams *params;
    int pid;
    int fds[2] = { -1, -1 };
    int error = 0;

    UNUSED(cfg);
    UNUSED(invoker);

    params = (ExecParams *) session->parameters;

    if ((error = pipe(fds)) < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to create pipes to child");
        goto out;
    }

    pid = fork();
    if (pid < 0) {
        cpn_log(LOG_LEVEL_ERROR, "Unable to fork");
        error = -1;
        goto out;
    }

    if (pid == 0) {
        while (dup2(fds[1], STDOUT_FILENO) < 0 && errno == EINTR);
        if (error < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to duplicate stdout: %s", strerror(errno));
            _exit(-1);
        }

        while (dup2(fds[1], STDERR_FILENO) < 0 && errno == EINTR);
        if (error < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to duplicate stdout: %s", strerror(errno));
            _exit(-1);
        }

        close(fds[0]);
        close(fds[1]);

        if (exec(params->command, (const char **) params->arguments, params->n_arguments) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to execute %s", params->command);
            _exit(-1);
        }

        _exit(0);
    } else {
        close(fds[1]);

        if (cpn_channel_relay(channel, 1, fds[0]) < 0) {
            cpn_log(LOG_LEVEL_ERROR, "Unable to relay exec output");
            error = -1;
            goto out;
        }
    }

out:
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);

    return error;
}

static int parse(ProtobufCMessage **out, int argc, const char *argv[])
{
    struct cpn_opt opts[] = {
        CPN_OPTS_OPT_STRING(0, "--command", NULL, NULL, false),
        CPN_OPTS_OPT_STRINGLIST(0, "--arguments", NULL, NULL, true),
        CPN_OPTS_OPT_END
    };
    ExecParams *params;
    uint32_t i;

    if (cpn_opts_parse(opts, argc, argv) < 0)
        return -1;

    params = malloc(sizeof(ExecParams));
    exec_params__init(params);

    params->command = strdup(opts[0].value.string);

    if (opts[1].set) {
        params->n_arguments = opts[1].value.stringlist.argc;
        params->arguments = malloc(sizeof(char *) * params->n_arguments);
        for (i = 0; i < params->n_arguments; i++) {
            params->arguments[i] = strdup(opts[1].value.stringlist.argv[i]);
        }
    } else {
        params->n_arguments = 0;
        params->arguments = NULL;
    }

    *out = &params->base;

    return 0;
}

int cpn_exec_init_service(const struct cpn_service_plugin **out)
{
    static struct cpn_service_plugin plugin = {
        "Shell",
        "exec",
        "0.0.1",
        handle,
        invoke,
        parse,
        &exec_params__descriptor
    };

    *out = &plugin;

    return 0;
}
