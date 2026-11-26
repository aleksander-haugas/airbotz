#ifndef AIRBOTZ_SSH_H
#define AIRBOTZ_SSH_H
#include <stdio.h>
int ssh_init(const char *path);
void ssh_process(void);
void ssh_shutdown(void);
#endif
