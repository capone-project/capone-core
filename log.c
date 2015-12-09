#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "log.h"

static enum log_level current_log_level = LOG_LEVEL_DEBUG;

static const char *log_levels[] = {
    "DEBUG",
    "VERBOSE",
    "WARNING",
    "ERROR",
};

void sd_log(enum log_level lvl, const char *msgformat, ...)
{
    char msg[3978], buf[4096], date[128];
    time_t t;
    struct tm *tm;
    va_list ap;

    if (lvl < current_log_level)
        return;

    t = time(NULL);
    tm = localtime(&t);
    strftime(date, sizeof(date), "%T", tm);

    va_start(ap, msgformat);
    vsnprintf(msg, sizeof(msg), msgformat, ap);
    va_end(ap);

    snprintf(buf, sizeof(buf), "%s - %s: %s", date, log_levels[lvl], msg);

    puts(buf);
}
