#ifndef AIRBOTZ_SSH_DETECTION_H
#define AIRBOTZ_SSH_DETECTION_H

#include "ssh_parser.h"

#include <stdint.h>

#define SSH_DETECTION_WINDOW_SECONDS 300U
#define SSH_DETECTION_BRUTE_FORCE_THRESHOLD 8U
#define SSH_DETECTION_SPRAY_ATTEMPT_THRESHOLD 8U
#define SSH_DETECTION_SPRAY_ACCOUNT_THRESHOLD 5U
#define SSH_DETECTION_SPRAY_PER_ACCOUNT_MAX 2U
#define SSH_DETECTION_DISTRIBUTED_ATTEMPT_THRESHOLD 8U
#define SSH_DETECTION_DISTRIBUTED_SOURCE_THRESHOLD 5U
#define SSH_DETECTION_DISTRIBUTED_PER_SOURCE_MAX 2U
#define SSH_DETECTION_DISTRIBUTED_SPRAY_ATTEMPT_THRESHOLD 8U
#define SSH_DETECTION_DISTRIBUTED_SPRAY_ACCOUNT_THRESHOLD 5U
#define SSH_DETECTION_DISTRIBUTED_SPRAY_SOURCE_THRESHOLD 5U
#define SSH_DETECTION_DISTRIBUTED_SPRAY_PER_ACCOUNT_MAX 2U
#define SSH_DETECTION_DISTRIBUTED_SPRAY_PER_SOURCE_MAX 4U
#define SSH_DETECTION_INVALID_ENUM_ATTEMPT_THRESHOLD 8U
#define SSH_DETECTION_INVALID_ENUM_ACCOUNT_THRESHOLD 5U
#define SSH_DETECTION_INVALID_ENUM_PER_ACCOUNT_MAX 2U
#define SSH_DETECTION_CAPACITY 4096U

struct ssh_detection_stats {
    unsigned long long auth_failures_observed;
    unsigned long long brute_force_findings;
    unsigned long long password_spray_findings;
    unsigned long long distributed_brute_force_findings;
    unsigned long long distributed_password_spray_findings;
    unsigned long long invalid_account_enumeration_findings;
    unsigned long long capacity_evictions;
    unsigned int active_observations;
    unsigned int partial_visibility;
};

/* Production entry point: timestamps observations with CLOCK_MONOTONIC. */
void ssh_detection_handle(const struct ssh_event *event);
/* Deterministic entry point for tests; now_ns is monotonic nanoseconds. */
void ssh_detection_process_at(const struct ssh_event *event, uint64_t now_ns);
void ssh_detection_get_stats(struct ssh_detection_stats *stats);
void ssh_detection_get_stats_at(struct ssh_detection_stats *stats, uint64_t now_ns);
void ssh_detection_reset(void);

#endif
