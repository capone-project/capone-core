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
#include <stdlib.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <sys/select.h>

#include <X11/Xlib.h>
#include <X11/extensions/XInput2.h>
#include <X11/extensions/XTest.h>

#include "lib/bench.h"
#include "lib/common.h"
#include "lib/channel.h"
#include "lib/server.h"

#define PORT "43269"

struct payload {
    const char *dpy1;
    const char *dpy2;
};

static int xinput;

static int setup_events(Display *dpy)
{
    XIEventMask mask[2];
    Window root;
    int dummy;

    if (!XQueryExtension(dpy, "XInputExtension", &xinput, &dummy, &dummy)) {
        puts("Could not query XInputExtension");
        return -1;
    }
    root = DefaultRootWindow(dpy);

    mask[0].deviceid = XIAllDevices;
    mask[0].mask_len = XIMaskLen(XI_LASTEVENT);
    mask[0].mask = calloc(mask[0].mask_len, sizeof(char));

    mask[1].deviceid = XIAllMasterDevices;
    mask[1].mask_len = XIMaskLen(XI_LASTEVENT);
    mask[1].mask = calloc(mask[1].mask_len, sizeof(char));
    XISetMask(mask[1].mask, XI_RawKeyPress);
    XISetMask(mask[1].mask, XI_RawButtonPress);

    XISelectEvents(dpy, root, &mask[0], 2);

    if (!XSync(dpy, False)) {
        puts("Could not sync display");
        return -1;
    }

    free(mask[0].mask);
    free(mask[1].mask);

    return 0;
}

void *process_events(void *ptr)
{
    struct payload *payload = (struct payload *) ptr;
    Display *dpy1, *dpy2;
    XEvent ev;
    uint64_t start, end;
    int x11fd1, x11fd2;
    fd_set fds;

    if (!(dpy1 = XOpenDisplay(payload->dpy1))) {
        printf("Could not open dpy %s\n", payload->dpy1);
        return NULL;
    }
    if (setup_events(dpy1) < 0) {
        printf("Could not setup events");
        return NULL;
    }
    x11fd1 = ConnectionNumber(dpy1);

    if (!(dpy2 = XOpenDisplay(payload->dpy2))) {
        printf("Could not open dpy %s\n", payload->dpy2);
        return NULL;
    }
    if (setup_events(dpy2) < 0) {
        printf("Could not setup events");
        return NULL;
    }
    x11fd2 = ConnectionNumber(dpy2);

    while (true) {
        FD_ZERO(&fds);

        FD_SET(x11fd1, &fds);
        FD_SET(x11fd2, &fds);

        select(MAX(x11fd1, x11fd2) + 1, &fds, NULL, NULL, NULL);

        if (FD_ISSET(x11fd1, &fds)) {
            XNextEvent(dpy1, &ev);
            start = sd_bench_nsecs();
            XNextEvent(dpy2, &ev);
            end = sd_bench_nsecs();
        } else if (FD_ISSET(x11fd2, &fds)) {
            XNextEvent(dpy2, &ev);
            start = sd_bench_nsecs();
            XNextEvent(dpy1, &ev);
            end = sd_bench_nsecs();
        } else {
            continue;
        }

        printf("delay (in ns): %"PRIu64"\n", end - start);
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    struct payload payload;
    struct sd_thread t;
    Display *dpy;
    int i, retval = 0;

    if (argc != 3) {
        printf("USAGE: %s <DISPLAY1> <DISPLAY2>\n", argv[0]);
        return -1;
    }

    payload.dpy1 = argv[1];
    payload.dpy2 = argv[2];

    sd_spawn(&t, process_events, &payload);

    if ((dpy = XOpenDisplay(argv[1])) == NULL) {
        retval = -1;
        goto out;
    }

    if (!XTestFakeRelativeMotionEvent(dpy, 2000, 0, CurrentTime)) {
        retval = -1;
        goto out;
    }

    XFlush(dpy);
    usleep(10000);

    for (i = 0; i < 10000; i++) {
        if (!XTestFakeButtonEvent(dpy, 1, True, CurrentTime)) {
            puts("Unable to generate fake button event");
            retval = -1;
            goto out;
        }
        XFlush(dpy);
        usleep(20);

        if (!XTestFakeButtonEvent(dpy, 1, False, CurrentTime)) {
            puts("Unable to generate fake button event");
            retval = -1;
            goto out;
        }
        XFlush(dpy);
        usleep(20);
    }

    usleep(10000);

out:
    sd_kill(&t);

    return retval;
}
