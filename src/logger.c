#include "../include/logger.h"
#include <stdio.h>

static int g_logger_level = LOG_WARN;

static void logger_print(int level, const char *label, const char *message) {
    if (level < g_logger_level) {
        return;
    }

    fprintf(stderr, "%s: %s\n", label, message == NULL ? "" : message);
}

void logger_set_level(int level) {
    g_logger_level = level;
}

void log_debug(const char *message) {
    logger_print(LOG_DEBUG, "debug", message);
}

void log_info(const char *message) {
    logger_print(LOG_INFO, "info", message);
}

void log_warn(const char *message) {
    logger_print(LOG_WARN, "warn", message);
}

void log_error(const char *message) {
    logger_print(LOG_ERROR, "error", message);
}
