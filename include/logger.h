#ifndef CADMUS_LOGGER_H
#define CADMUS_LOGGER_H

/*
 * Levelled logging to stderr.
 * Assigned to: Thrishaan
 */

#define LOG_DEBUG 0
#define LOG_INFO  1
#define LOG_WARN  2
#define LOG_ERROR 3

/* Thrishaan set minimum level; messages below it are discarded */
void logger_set_level(int level);

/* Thrishaan */
void log_debug(const char *fmt, ...);
void log_info (const char *fmt, ...);
void log_warn (const char *fmt, ...);
void log_error(const char *fmt, ...);

#endif /* CADMUS_LOGGER_H */
