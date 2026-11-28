#include "ssh_detection.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NS_PER_SECOND UINT64_C(1000000000)
#define WARMUP_EVENTS SSH_DETECTION_CAPACITY
#define EVENTS_PER_SAMPLE 5000U
#define SAMPLE_COUNT 5U

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

static void
sort_samples(uint64_t *samples, unsigned int count)
{
    unsigned int i;

    for (i = 1; i < count; ++i) {
        uint64_t value = samples[i];
        unsigned int j = i;

        while (j > 0 && samples[j - 1U] > value) {
            samples[j] = samples[j - 1U];
            --j;
        }
        samples[j] = value;
    }
}

int
main(void)
{
    struct ssh_event event;
    struct ssh_event *events;
    uint64_t samples[SAMPLE_COUNT];
    uint64_t start, finish, now_ns, sample_time_ns;
    uint64_t minimum, maximum, median;
    unsigned int i, j, sequence = 0;
    double events_per_second, spread_percent;

    events = calloc(EVENTS_PER_SAMPLE, sizeof(*events));
    if (events == NULL) {
        perror("calloc benchmark events");
        return 1;
    }

    if (logger_init("/dev/null") != 0) {
        perror("logger_init");
        free(events);
        return 1;
    }

    ssh_detection_reset();
    now_ns = monotonic_ns();
    if (now_ns == 0) {
        fprintf(stderr, "clock_gettime(CLOCK_MONOTONIC) failed\n");
        logger_close();
        free(events);
        return 1;
    }

    for (i = 0; i < WARMUP_EVENTS; ++i) {
        make_failure(&event, sequence);
        ssh_detection_process_at(&event,
            now_ns + (uint64_t)sequence * 1000000U);
        ++sequence;
    }

    for (i = 0; i < SAMPLE_COUNT; ++i) {
        /*
         * Prepare unique source/account events outside the timed interval.
         * The measured region therefore focuses on detector processing,
         * not snprintf() or synthetic event construction.
         */
        for (j = 0; j < EVENTS_PER_SAMPLE; ++j) {
            make_failure(&events[j], sequence);
            ++sequence;
        }
        sample_time_ns = now_ns + (uint64_t)sequence * 1000000U;

        start = monotonic_ns();
        if (start == 0) {
            fprintf(stderr, "clock_gettime start failed\n");
            logger_close();
            free(events);
            return 1;
        }

        for (j = 0; j < EVENTS_PER_SAMPLE; ++j) {
            ssh_detection_process_at(&events[j],
                sample_time_ns + (uint64_t)j * 1000000U);
        }

        finish = monotonic_ns();
        if (finish <= start) {
            fprintf(stderr, "invalid monotonic benchmark interval\n");
            logger_close();
            free(events);
            return 1;
        }
        samples[i] = (finish - start) / EVENTS_PER_SAMPLE;
    }

    logger_close();
    free(events);
    sort_samples(samples, SAMPLE_COUNT);
    minimum = samples[0];
    median = samples[SAMPLE_COUNT / 2U];
    maximum = samples[SAMPLE_COUNT - 1U];
    spread_percent = minimum == 0 ? 0.0 :
        ((double)(maximum - minimum) * 100.0) / (double)minimum;

    printf("SSH detection synthetic benchmark\n");
    printf("warmup_events=%u samples=%u events_per_sample=%u total_measured_events=%u active_capacity=%u\n",
           WARMUP_EVENTS, SAMPLE_COUNT, EVENTS_PER_SAMPLE,
           SAMPLE_COUNT * EVENTS_PER_SAMPLE, SSH_DETECTION_CAPACITY);
    for (i = 0; i < SAMPLE_COUNT; ++i) {
        events_per_second = 1000000000.0 / (double)samples[i];
        printf("sample_%u ns_per_event=%llu events_per_second=%.0f\n",
               i + 1U, (unsigned long long)samples[i], events_per_second);
    }
    events_per_second = 1000000000.0 / (double)median;
    printf("median_ns_per_event=%llu median_events_per_second=%.0f\n",
           (unsigned long long)median, events_per_second);
    printf("min_ns_per_event=%llu max_ns_per_event=%llu spread_percent=%.1f\n",
           (unsigned long long)minimum, (unsigned long long)maximum,
           spread_percent);
    printf("scenario=full_ring_unique_source_and_account logging=/dev/null event_building=outside_timed_region\n");
    return 0;
}
