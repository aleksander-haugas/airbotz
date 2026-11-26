#ifndef AIRBOTZ_LOGGER_H
#define AIRBOTZ_LOGGER_H
int logger_init(const char *path);
void logger_log(const char *level, const char *fmt, ...);
void logger_close(void);
#endif
