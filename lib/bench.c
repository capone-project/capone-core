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

#include <stdio.h>

#include "config.h"

#ifdef HAVE_SCHED
# define __USE_GNU
#  include <sched.h>
#  include <pthread.h>
# undef __USE_GNU
#endif

#ifdef HAVE_CLOCK_GETTIME
# include <time.h>
#else
# include <sys/time.h>
#endif

#include "lib/common.h"

#include "bench.h"

uint64_t cpn_bench_nsecs(void)
{
#ifdef HAVE_CLOCK_GETTIME
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);

    return t.tv_sec * 1000000000 + t.tv_nsec;
#else
    struct timeval t;

    gettimeofday(&t, NULL);

    return t.tv_sec * 1000000000 + t.tv_usec * 1000;
#endif
}

int cpn_bench_set_affinity(uint8_t cpu)
{
#ifdef HAVE_SCHED
    cpu_set_t mask;
    pthread_t t;

    t = pthread_self();

    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);

    return pthread_setaffinity_np(t, sizeof(mask), &mask);
#else
    UNUSED(cpu);
    return 0;
#endif
}
