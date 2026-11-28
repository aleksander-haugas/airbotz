#include "ssh_detection.h"
#include "logger.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define NS_PER_SECOND UINT64_C(1000000000)
#define WARMUP_EVENTS SSH_DETECTION_CAPACITY
#define MEASURED_EVENTS 10000U

static uint64_t
monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * NS_PER_SECOND + (uint64_t)ts.tv_nsec;
}

static void
make_failure(struct ssh_event *event, unsigned int sequence)
{
    unsigned int address = sequence % 131072U;
    unsigned int octet2 = 18U + ((address >> 16) & 1U);
    unsigned int octet3 = (address >> 8) & 255U;
    unsigned int octet4 = address & 255U;

    memset(event, 0, sizeof(*event));
    event->type = SSH_EVENT_FAILED_PASSWORD;
    event->has_address = 1;
    (void)snprintf(event->address, sizeof(event->address),
                   "198.%u.%u.%u", octet2, octet3, octet4);
    event->has_username = 1;
    (void)snprintf(event->username, sizeof(event->username),
                   "bench-user-%u", sequence);
}

int
main(void)
{
    struct ssh_event event;
    uint64_t start, finish, now_ns;
    unsigned int i;
    double elapsed, ns_per_event, events_per_second;

    if (logger_init("/dev/null") != 0) {
        perror("logger_init");
        return 1;
    }

    ssh_detection_reset();
    now_ns = monotonic_ns();
    if (now_ns == 0) {
        fprintf(stderr, "clock_gettime(CLOCK_MONOTONIC) failed\n");
        logger_close();
        return 1;
    }

    for (i = 0; i < WARMUP_EVENTS; ++i) {
        make_failure(&event, i);
        ssh_detection_process_at(&event, now_ns + (uint64_t)i * 1000000U);
    }

    start = monotonic_ns();
    for (i = 0; i < MEASURED_EVENTS; ++i) {
        make_failure(&event, WARMUP_EVENTS + i);
        ssh_detection_process_at(&event,
            now_ns + (uint64_t)(WARMUP_EVENTS + i) * 1000000U);
    }
    finish = monotonic_ns();
    logger_close();

    if (finish <= start) {
        fprintf(stderr, "invalid monotonic benchmark interval\n");
        return 1;
    }

    elapsed = (double)(finish - start) / 1000000000.0;
    ns_per_event = (double)(finish - start) / MEASURED_EVENTS;
    events_per_second = MEASURED_EVENTS / elapsed;

    printf("SSH detection synthetic benchmark\n");
    printf("warmup_events=%u measured_events=%u active_capacity=%u\n",
           WARMUP_EVENTS, MEASURED_EVENTS, SSH_DETECTION_CAPACITY);
    printf("elapsed_seconds=%.6f ns_per_event=%.0f events_per_second=%.0f\n",
           elapsed, ns_per_event, events_per_second);
    printf("scenario=full_ring_unique_source_and_account logging=/dev/null\n");
    return 0;
}
