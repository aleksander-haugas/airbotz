#ifndef AIRBOTZ_SSH_H
#define AIRBOTZ_SSH_H

#include "ssh_parser.h"

typedef void (*ssh_event_handler)(const struct ssh_event *event,
                                  void *context);

int ssh_init(const char *path, ssh_event_handler handler, void *context);
void ssh_process(void);
void ssh_shutdown(void);

#endif
