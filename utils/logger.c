// Logging structuré

#include "logger.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static FILE* log_file = NULL;
static LogLevel current_min_level = LOG_LEVEL_INFO;
// static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char* level_to_string(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_FATAL: return "FATAL";
        default:              return "UNKNOWN";
    }
}

int logger_init(const char* log_file_path, LogLevel min_level) {
    current_min_level = min_level;

    if (log_file_path != NULL) {
        log_file = fopen(log_file_path, "a");
        if (!log_file) {
            fprintf(stderr, "FATAL : Cannot create logging file %s\n", log_file_path);
            return -1;
        }
    }
    return 0;
}

void logger_close(void) {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

void logger_log(LogLevel level, const char* file, int line, const char* format, ...) {
    if (level < current_min_level) {
        return;
    }

    // pthread_mutex_lock(&log_mutex);

    time_t current_time = time(NULL);
    struct tm* t = localtime(&current_time);
    char time_buf[24];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    FILE* console_stream = (level >= LOG_LEVEL_WARN) ? stderr : stdout;

    fprintf(console_stream, "[%s] [%s] %s:%d - ", time_buf, level_to_string(level), file, line);
    va_list args1;
    va_start(args1, format);
    vfprintf(console_stream, format, args1);
    va_end(args1);
    fprintf(console_stream, "\n");

    if (log_file) {
        fprintf(log_file, "[%s] [%s] %s:%d - ", time_buf, level_to_string(level), file, line);
        va_list args2;
        va_start(args2, format);
        vfprintf(log_file, format, args2);
        va_end(args2);
        fprintf(log_file, "\n");
        fflush(log_file);
    }

    // pthread_mutex_unlock(&log_mutex);
}