#ifndef CADMUS_LOGGER_H
#define CADMUS_LOGGER_H

/*
 * Levelled logging to stderr.
 */

#define LOG_DEBUG 0
#define LOG_INFO  1
#define LOG_WARN  2
#define LOG_ERROR 3

/* Set the minimum log level; lower-priority messages are discarded. */
void logger_set_level(int level);

/* Emit a debug-level message. */
void log_debug(const char *message);
/* Emit an info-level message. */
void log_info (const char *message);
/* Emit a warning-level message. */
void log_warn (const char *message);
/* Emit an error-level message. */
void log_error(const char *message);

#endif /* CADMUS_LOGGER_H */
