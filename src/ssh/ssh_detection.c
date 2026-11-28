#include "ssh_detection.h"
#include "logger.h"

#include <string.h>
#include <time.h>
#include <limits.h>

#define NS_PER_SECOND UINT64_C(1000000000)
#define WINDOW_NS ((uint64_t)SSH_DETECTION_WINDOW_SECONDS * NS_PER_SECOND)

struct auth_observation {
    uint64_t observed_ns;
    unsigned int weight;
    char address[SSH_EVENT_IP_MAX];
};

static struct auth_observation observations[SSH_DETECTION_CAPACITY];
static unsigned int head;
static unsigned int count;
static uint64_t last_now_ns;
static uint64_t degraded_until_ns;
static struct ssh_detection_stats detection_stats;

static void
increment_saturated(unsigned long long *value)
{
    if (*value != ULLONG_MAX)
        ++*value;
}

static uint64_t
window_start(uint64_t now_ns)
{
    return now_ns > WINDOW_NS ? now_ns - WINDOW_NS : 0;
}

static void
expire_observations(uint64_t now_ns)
{
    uint64_t cutoff = window_start(now_ns);

    while (count != 0) {
        struct auth_observation *oldest = &observations[head];

        if (oldest->observed_ns >= cutoff)
            break;
        memset(oldest, 0, sizeof(*oldest));
        head = (head + 1U) % SSH_DETECTION_CAPACITY;
        --count;
    }

    detection_stats.active_observations = count;
    detection_stats.partial_visibility =
        degraded_until_ns != 0 && now_ns < degraded_until_ns;
    if (!detection_stats.partial_visibility)
        degraded_until_ns = 0;
}

static unsigned long long
count_source_failures(const char *address)
{
    unsigned long long total = 0;
    unsigned int i;

    for (i = 0; i < count; ++i) {
        const struct auth_observation *item =
            &observations[(head + i) % SSH_DETECTION_CAPACITY];

        if (strcmp(item->address, address) == 0) {
            if (ULLONG_MAX - total < item->weight)
                return ULLONG_MAX;
            total += item->weight;
        }
    }
    return total;
}

void
ssh_detection_process_at(const struct ssh_event *event, uint64_t now_ns)
{
    unsigned long long previous, current;
    unsigned int weight;
    unsigned int tail;
    struct auth_observation *slot;

    if (!event)
        return;

    /* CLOCK_MONOTONIC cannot go backwards; clamp defensive/test anomalies. */
    if (now_ns < last_now_ns)
        now_ns = last_now_ns;
    last_now_ns = now_ns;
    expire_observations(now_ns);

    /*
     * Count only explicit failed-password records. PAM summaries, invalid-user
     * diagnostics and transport errors may describe the same interaction and
     * are deliberately not counted as independent authentication attempts.
     */
    if (event->type != SSH_EVENT_FAILED_PASSWORD || !event->has_address ||
        event->address[0] == '\0')
        return;

    weight = event->is_repetition_summary ? event->repetition_count : 1U;
    if (weight == 0)
        return;

    increment_saturated(&detection_stats.auth_failures_observed);
    previous = count_source_failures(event->address);

    if (count == SSH_DETECTION_CAPACITY) {
        memset(&observations[head], 0, sizeof(observations[head]));
        head = (head + 1U) % SSH_DETECTION_CAPACITY;
        --count;
        increment_saturated(&detection_stats.capacity_evictions);
        degraded_until_ns = now_ns > UINT64_MAX - WINDOW_NS ?
            UINT64_MAX : now_ns + WINDOW_NS;
    }

    tail = (head + count) % SSH_DETECTION_CAPACITY;
    slot = &observations[tail];
    memset(slot, 0, sizeof(*slot));
    slot->observed_ns = now_ns;
    slot->weight = weight;
    (void)snprintf(slot->address, sizeof(slot->address), "%s", event->address);
    ++count;
    detection_stats.active_observations = count;
    detection_stats.partial_visibility =
        degraded_until_ns != 0 && now_ns < degraded_until_ns;

    current = count_source_failures(event->address);
    if (previous < SSH_DETECTION_BRUTE_FORCE_THRESHOLD &&
        current >= SSH_DETECTION_BRUTE_FORCE_THRESHOLD) {
        increment_saturated(&detection_stats.brute_force_findings);
        logger_log("SSH_DETECTION",
            "rule=ssh.bruteforce.source address=%s failures=%llu window_seconds=%u threshold=%u confidence=%s evidence=failed_password_records",
            event->address, current, SSH_DETECTION_WINDOW_SECONDS,
            SSH_DETECTION_BRUTE_FORCE_THRESHOLD,
            detection_stats.partial_visibility ? "reduced" : "moderate");
    }
}

void
ssh_detection_handle(const struct ssh_event *event)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return;
    ssh_detection_process_at(event,
        (uint64_t)ts.tv_sec * NS_PER_SECOND + (uint64_t)ts.tv_nsec);
}

void
ssh_detection_get_stats(struct ssh_detection_stats *stats)
{
    if (!stats)
        return;
    *stats = detection_stats;
    stats->active_observations = count;
    stats->partial_visibility =
        degraded_until_ns != 0 && last_now_ns < degraded_until_ns;
}

void
ssh_detection_reset(void)
{
    memset(observations, 0, sizeof(observations));
    memset(&detection_stats, 0, sizeof(detection_stats));
    head = 0;
    count = 0;
    last_now_ns = 0;
    degraded_until_ns = 0;
}
