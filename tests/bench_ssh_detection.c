#include "ssh_detection.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NS_PER_SECOND UINT64_C(1000000000)
#define WARMUP_EVENTS SSH_DETECTION_CAPACITY
#define EVENTS_PER_SAMPLE 2500U
#define SAMPLE_COUNT 5U

enum benchmark_scenario {
    BENCH_MIXED_NORMAL = 0,
    BENCH_SOURCE_BRUTE_FORCE,
    BENCH_SOURCE_SPRAY,
    BENCH_DISTRIBUTED_SPRAY,
    BENCH_HIGH_CARDINALITY,
    BENCH_SCENARIO_COUNT
};

struct scenario_info {
    enum benchmark_scenario id;
    const char *name;
};

static const struct scenario_info scenarios[] = {
    {BENCH_MIXED_NORMAL, "mixed_normal_98.98pct_accepted_1pct_pam_0.02pct_failed"},
    {BENCH_SOURCE_BRUTE_FORCE, "source_account_bruteforce"},
    {BENCH_SOURCE_SPRAY, "single_source_password_spray"},
    {BENCH_DISTRIBUTED_SPRAY, "distributed_password_spray"},
    {BENCH_HIGH_CARDINALITY, "full_ring_unique_source_and_account"}
};

static uint64_t
monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * NS_PER_SECOND + (uint64_t)ts.tv_nsec;
}

static void
make_address(char *output, size_t output_size, unsigned int sequence)
{
    unsigned int address = sequence % 131072U;
    unsigned int octet2 = 18U + ((address >> 16) & 1U);
    unsigned int octet3 = (address >> 8) & 255U;
    unsigned int octet4 = address & 255U;

    (void)snprintf(output, output_size, "198.%u.%u.%u",
                   octet2, octet3, octet4);
}

static void
set_identity(struct ssh_event *event, unsigned int source_id,
             unsigned int account_id, unsigned int session_id)
{
    make_address(event->address, sizeof(event->address), source_id);
    event->has_address = 1;
    event->has_username = 1;
    (void)snprintf(event->username, sizeof(event->username),
                   "bench-user-%u", account_id);
    event->has_port = 1;
    event->port = 40000U + (session_id % 20000U);
    event->has_pid = 1;
    (void)snprintf(event->pid, sizeof(event->pid), "%u",
                   1000U + (session_id % 50000U));
}

static void
make_benchmark_event(struct ssh_event *event,
                     enum benchmark_scenario scenario,
                     unsigned int sequence)
{
    unsigned int source_id = sequence;
    unsigned int account_id = sequence;
    unsigned int session_id = sequence;

    memset(event, 0, sizeof(*event));

    switch (scenario) {
    case BENCH_MIXED_NORMAL:
        /*
         * One isolated failure every 2500 records, followed by a success
         * on the same tuple. Other records are mostly accepted auth with
         * a small amount of PAM noise; this stays below detection thresholds.
         */
        if ((sequence % 5000U) == 0U) {
            session_id = sequence;
            event->type = SSH_EVENT_FAILED_PASSWORD;
        } else if ((sequence % 2500U) == 1U) {
            session_id = sequence - 1U;
            event->type = SSH_EVENT_ACCEPTED_PASSWORD;
        } else if ((sequence % 100U) == 2U) {
            session_id = sequence;
            event->type = SSH_EVENT_PAM_AUTH_FAILURE;
        } else {
            session_id = sequence;
            event->type = SSH_EVENT_ACCEPTED_PASSWORD;
        }
        source_id = session_id;
        account_id = session_id;
        set_identity(event, source_id, account_id, session_id);
        break;

    case BENCH_SOURCE_BRUTE_FORCE:
        event->type = SSH_EVENT_FAILED_PASSWORD;
        set_identity(event, 1U, 1U, sequence);
        break;

    case BENCH_SOURCE_SPRAY:
        event->type = SSH_EVENT_FAILED_PASSWORD;
        set_identity(event, 1U, sequence % 8192U, sequence);
        break;

    case BENCH_DISTRIBUTED_SPRAY:
        event->type = SSH_EVENT_FAILED_PASSWORD;
        set_identity(event, sequence % 8192U, (sequence * 3U) % 8192U, sequence);
        break;

    case BENCH_HIGH_CARDINALITY:
    default:
        event->type = SSH_EVENT_FAILED_PASSWORD;
        set_identity(event, source_id, account_id, session_id);
        /* Exercise high-cardinality source events with no parsed username. */
        event->has_username = 0;
        event->username[0] = '\0';
        break;
    }
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

static int
run_scenario(const struct scenario_info *scenario,
             struct ssh_event *events)
{
    uint64_t samples[SAMPLE_COUNT];
    struct ssh_detection_stats stats;
    uint64_t now_ns, sample_time_ns, start, finish;
    uint64_t minimum, maximum, median;
    unsigned int i, j, sequence = 0;
    double events_per_second, spread_percent;

    ssh_detection_reset();
    now_ns = monotonic_ns();
    if (now_ns == 0) {
        fprintf(stderr, "clock_gettime(CLOCK_MONOTONIC) failed\n");
        return -1;
    }

    for (i = 0; i < WARMUP_EVENTS; ++i) {
        make_benchmark_event(&events[0], scenario->id, sequence);
        ssh_detection_process_at(&events[0],
            now_ns + (uint64_t)sequence * 1000000U);
        ++sequence;
    }

    for (i = 0; i < SAMPLE_COUNT; ++i) {
        /*
         * Prepare event structures and synthetic identity strings outside
         * the timed interval. The measured region calls only the detector.
         */
        for (j = 0; j < EVENTS_PER_SAMPLE; ++j) {
            make_benchmark_event(&events[j], scenario->id, sequence);
            ++sequence;
        }
        sample_time_ns = now_ns + (uint64_t)sequence * 1000000U;

        start = monotonic_ns();
        if (start == 0) {
            fprintf(stderr, "clock_gettime start failed\n");
            return -1;
        }

        for (j = 0; j < EVENTS_PER_SAMPLE; ++j) {
            ssh_detection_process_at(&events[j],
                sample_time_ns + (uint64_t)j * 1000000U);
        }

        finish = monotonic_ns();
        if (finish <= start) {
            fprintf(stderr, "invalid monotonic benchmark interval\n");
            return -1;
        }
        samples[i] = (finish - start) / EVENTS_PER_SAMPLE;
    }

    sort_samples(samples, SAMPLE_COUNT);
    minimum = samples[0];
    median = samples[SAMPLE_COUNT / 2U];
    maximum = samples[SAMPLE_COUNT - 1U];
    spread_percent = minimum == 0 ? 0.0 :
        ((double)(maximum - minimum) * 100.0) / (double)minimum;

    printf("scenario=%s\n", scenario->name);
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
    printf("\n");
    return 0;
}

int
main(void)
{
    struct ssh_event *events;
    unsigned int i;

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

    printf("SSH detection synthetic workload benchmark\n");
    printf("event_building=outside_timed_region logging=/dev/null\n\n");

    for (i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); ++i) {
        if (run_scenario(&scenarios[i], events) != 0) {
            logger_close();
            free(events);
            return 1;
        }
    }

    logger_close();
    free(events);
    return 0;
}
