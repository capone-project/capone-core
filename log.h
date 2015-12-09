enum log_level {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_VERBOSE,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
};

extern void sd_log(enum log_level lvl, const char *msgformat, ...);
