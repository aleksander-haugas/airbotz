#ifndef AIRBOTZ_SSH_H
#define AIRBOTZ_SSH_H

#include "ssh_parser.h"

#include <time.h>

struct ssh_reader_stats {
    unsigned long long records_seen, records_parsed;
    unsigned long long events_classified, events_unknown;
    unsigned long long records_malformed, records_oversized;
    unsigned long long read_errors, rotations;
    unsigned long long missing_transitions, recovery_transitions;
    time_t last_read_time, last_record_time;
    int source_available;
};

typedef void (*ssh_event_handler)(const struct ssh_event *event,
                                  void *context);

int ssh_init(const char *path, ssh_event_handler handler, void *context);
void ssh_process(void);
void ssh_get_stats(struct ssh_reader_stats *stats);
void ssh_shutdown(void);

#endif
