#ifndef AIRBOTZ_CORE_H
#define AIRBOTZ_CORE_H
#include "config.h"
int core_init(const char *config_path);
int core_run(void);
void core_shutdown(void);
#endif
