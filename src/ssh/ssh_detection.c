#include "ssh_detection.h"
#include "logger.h"

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define NS_PER_SECOND UINT64_C(1000000000)
#define WINDOW_NS ((uint64_t)SSH_DETECTION_WINDOW_SECONDS * NS_PER_SECOND)

struct auth_observation {
    uint64_t observed_ns;
    unsigned int weight;
    unsigned int invalid_user;
    char address[SSH_EVENT_IP_MAX];
    char username[SSH_EVENT_USER_MAX];
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

static int
canonicalize_address(const char *input, char *output, size_t output_size)
{
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (!input || !output || output_size == 0 ||
        memchr(input, '\0', SSH_EVENT_IP_MAX) == NULL || input[0] == '\0')
        return 0;

    if (inet_pton(AF_INET, input, &ipv4) == 1)
        return inet_ntop(AF_INET, &ipv4, output, output_size) != NULL;
    if (inet_pton(AF_INET6, input, &ipv6) == 1)
        return inet_ntop(AF_INET6, &ipv6, output, output_size) != NULL;
    return 0;
}

static unsigned long long
count_source_user_failures(const char *address, const char *username)
{
    unsigned long long total = 0;
    unsigned int i;

    for (i = 0; i < count; ++i) {
        const struct auth_observation *item =
            &observations[(head + i) % SSH_DETECTION_CAPACITY];

        if (strcmp(item->address, address) == 0 &&
            strcmp(item->username, username) == 0) {
            if (ULLONG_MAX - total < item->weight)
                return ULLONG_MAX;
            total += item->weight;
        }
    }
    return total;
}

#define SPRAY_HASH_CAPACITY 8192U

struct spray_bucket {
    uint16_t observation_index;
    uint8_t weight;
};

struct spray_metrics {
    unsigned long long total_attempts;
    unsigned int distinct_accounts;
    unsigned long long maximum_account_attempts;
};

static unsigned int
username_hash(const char *username)
{
    unsigned int hash = 2166136261U;

    while (*username) {
        hash ^= (unsigned char)*username++;
        hash *= 16777619U;
    }
    return hash;
}

static struct spray_metrics
get_spray_metrics(const char *address)
{
    struct spray_bucket buckets[SPRAY_HASH_CAPACITY];
    struct spray_metrics metrics = {0, 0, 0};
    unsigned int i;

    memset(buckets, 0, sizeof(buckets));
    for (i = 0; i < count; ++i) {
        const struct auth_observation *item =
            &observations[(head + i) % SSH_DETECTION_CAPACITY];
        unsigned int slot;
        unsigned int probes;

        if (strcmp(item->address, address) != 0 ||
            item->username[0] == '\0')
            continue;
        if (ULLONG_MAX - metrics.total_attempts < item->weight)
            metrics.total_attempts = ULLONG_MAX;
        else
            metrics.total_attempts += item->weight;

        slot = username_hash(item->username) & (SPRAY_HASH_CAPACITY - 1U);
        for (probes = 0; probes < SPRAY_HASH_CAPACITY; ++probes) {
            struct spray_bucket *bucket = &buckets[slot];

            if (bucket->observation_index == 0) {
                bucket->observation_index = (uint16_t)(i + 1U);
                bucket->weight = item->weight >
                    SSH_DETECTION_SPRAY_PER_ACCOUNT_MAX ?
                    SSH_DETECTION_SPRAY_PER_ACCOUNT_MAX + 1U : item->weight;
                ++metrics.distinct_accounts;
                break;
            }
            if (strcmp(observations[(head +
                    bucket->observation_index - 1U) %
                    SSH_DETECTION_CAPACITY].username, item->username) == 0) {
                if (bucket->weight <= SSH_DETECTION_SPRAY_PER_ACCOUNT_MAX) {
                    if (item->weight >
                        SSH_DETECTION_SPRAY_PER_ACCOUNT_MAX - bucket->weight)
                        bucket->weight =
                            SSH_DETECTION_SPRAY_PER_ACCOUNT_MAX + 1U;
                    else
                        bucket->weight += item->weight;
                }
                break;
            }
            slot = (slot + 1U) & (SPRAY_HASH_CAPACITY - 1U);
        }
    }

    for (i = 0; i < SPRAY_HASH_CAPACITY; ++i) {
        if (buckets[i].observation_index != 0 &&
            buckets[i].weight > metrics.maximum_account_attempts)
            metrics.maximum_account_attempts = buckets[i].weight;
    }
    return metrics;
}

#define DISTRIBUTED_HASH_CAPACITY 8192U

struct distributed_bucket {
    uint16_t observation_index;
    uint8_t weight;
};

struct distributed_metrics {
    unsigned long long total_attempts;
    unsigned int distinct_sources;
    unsigned int maximum_source_attempts;
};

static unsigned int
address_hash(const char *address)
{
    unsigned int hash = 2166136261U;

    while (*address) {
        hash ^= (unsigned char)*address++;
        hash *= 16777619U;
    }
    return hash;
}


static struct spray_metrics
get_invalid_user_metrics(const char *address)
{
    struct spray_bucket buckets[SPRAY_HASH_CAPACITY];
    struct spray_metrics metrics = {0, 0, 0};
    unsigned int i;

    memset(buckets, 0, sizeof(buckets));
    for (i = 0; i < count; ++i) {
        const struct auth_observation *item =
            &observations[(head + i) % SSH_DETECTION_CAPACITY];
        unsigned int slot, probes;

        if (!item->invalid_user || strcmp(item->address, address) != 0 ||
            item->username[0] == '\0')
            continue;
        if (ULLONG_MAX - metrics.total_attempts < item->weight)
            metrics.total_attempts = ULLONG_MAX;
        else
            metrics.total_attempts += item->weight;

        slot = username_hash(item->username) & (SPRAY_HASH_CAPACITY - 1U);
        for (probes = 0; probes < SPRAY_HASH_CAPACITY; ++probes) {
            struct spray_bucket *bucket = &buckets[slot];
            if (bucket->observation_index == 0) {
                bucket->observation_index = (uint16_t)(i + 1U);
                bucket->weight = item->weight > SSH_DETECTION_INVALID_ENUM_PER_ACCOUNT_MAX ?
                    SSH_DETECTION_INVALID_ENUM_PER_ACCOUNT_MAX + 1U : item->weight;
                ++metrics.distinct_accounts;
                break;
            }
            if (strcmp(observations[(head + bucket->observation_index - 1U) %
                    SSH_DETECTION_CAPACITY].username, item->username) == 0) {
                if (bucket->weight <= SSH_DETECTION_INVALID_ENUM_PER_ACCOUNT_MAX) {
                    if (item->weight > SSH_DETECTION_INVALID_ENUM_PER_ACCOUNT_MAX - bucket->weight)
                        bucket->weight = SSH_DETECTION_INVALID_ENUM_PER_ACCOUNT_MAX + 1U;
                    else
                        bucket->weight += item->weight;
                }
                break;
            }
            slot = (slot + 1U) & (SPRAY_HASH_CAPACITY - 1U);
        }
    }
    for (i = 0; i < SPRAY_HASH_CAPACITY; ++i)
        if (buckets[i].observation_index != 0 &&
            buckets[i].weight > metrics.maximum_account_attempts)
            metrics.maximum_account_attempts = buckets[i].weight;
    return metrics;
}

static int
is_invalid_account_enumeration(const struct spray_metrics *metrics)
{
    return metrics->total_attempts >= SSH_DETECTION_INVALID_ENUM_ATTEMPT_THRESHOLD &&
        metrics->distinct_accounts >= SSH_DETECTION_INVALID_ENUM_ACCOUNT_THRESHOLD &&
        metrics->maximum_account_attempts <= SSH_DETECTION_INVALID_ENUM_PER_ACCOUNT_MAX;
}

static struct distributed_metrics
get_distributed_metrics(const char *username)
{
    struct distributed_bucket buckets[DISTRIBUTED_HASH_CAPACITY];
    struct distributed_metrics metrics = {0, 0, 0};
    unsigned int i;

    memset(buckets, 0, sizeof(buckets));
    for (i = 0; i < count; ++i) {
        const struct auth_observation *item =
            &observations[(head + i) % SSH_DETECTION_CAPACITY];
        unsigned int slot;
        unsigned int probes;

        if (item->username[0] == '\0' ||
            strcmp(item->username, username) != 0)
            continue;

        if (ULLONG_MAX - metrics.total_attempts < item->weight)
            metrics.total_attempts = ULLONG_MAX;
        else
            metrics.total_attempts += item->weight;

        slot = address_hash(item->address) &
            (DISTRIBUTED_HASH_CAPACITY - 1U);
        for (probes = 0; probes < DISTRIBUTED_HASH_CAPACITY; ++probes) {
            struct distributed_bucket *bucket = &buckets[slot];

            if (bucket->observation_index == 0) {
                bucket->observation_index = (uint16_t)(i + 1U);
                bucket->weight = item->weight >
                    SSH_DETECTION_DISTRIBUTED_PER_SOURCE_MAX ?
                    SSH_DETECTION_DISTRIBUTED_PER_SOURCE_MAX + 1U :
                    item->weight;
                ++metrics.distinct_sources;
                break;
            }
            if (strcmp(observations[(head +
                    bucket->observation_index - 1U) %
                    SSH_DETECTION_CAPACITY].address, item->address) == 0) {
                if (bucket->weight <=
                    SSH_DETECTION_DISTRIBUTED_PER_SOURCE_MAX) {
                    if (item->weight >
                        SSH_DETECTION_DISTRIBUTED_PER_SOURCE_MAX -
                        bucket->weight)
                        bucket->weight =
                            SSH_DETECTION_DISTRIBUTED_PER_SOURCE_MAX + 1U;
                    else
                        bucket->weight += item->weight;
                }
                break;
            }
            slot = (slot + 1U) & (DISTRIBUTED_HASH_CAPACITY - 1U);
        }
    }

    for (i = 0; i < DISTRIBUTED_HASH_CAPACITY; ++i) {
        if (buckets[i].observation_index != 0 &&
            buckets[i].weight > metrics.maximum_source_attempts)
            metrics.maximum_source_attempts = buckets[i].weight;
    }
    return metrics;
}


struct distributed_spray_metrics {
    unsigned long long total_attempts;
    unsigned int distinct_accounts;
    unsigned int distinct_sources;
    unsigned int maximum_account_attempts;
    unsigned int maximum_source_attempts;
};

static struct distributed_spray_metrics
get_distributed_spray_metrics(void)
{
    struct spray_bucket buckets[SPRAY_HASH_CAPACITY];
    struct distributed_spray_metrics metrics = {0, 0, 0, 0, 0};
    unsigned int i;

    memset(buckets, 0, sizeof(buckets));
    for (i = 0; i < count; ++i) {
        const struct auth_observation *item =
            &observations[(head + i) % SSH_DETECTION_CAPACITY];
        unsigned int slot, probes;
        if (item->username[0] == '\0')
            continue;
        if (ULLONG_MAX - metrics.total_attempts < item->weight)
            metrics.total_attempts = ULLONG_MAX;
        else
            metrics.total_attempts += item->weight;
        slot = username_hash(item->username) & (SPRAY_HASH_CAPACITY - 1U);
        for (probes = 0; probes < SPRAY_HASH_CAPACITY; ++probes) {
            struct spray_bucket *bucket = &buckets[slot];
            if (bucket->observation_index == 0) {
                bucket->observation_index = (uint16_t)(i + 1U);
                bucket->weight = item->weight > SSH_DETECTION_DISTRIBUTED_SPRAY_PER_ACCOUNT_MAX ?
                    SSH_DETECTION_DISTRIBUTED_SPRAY_PER_ACCOUNT_MAX + 1U : item->weight;
                ++metrics.distinct_accounts;
                break;
            }
            if (strcmp(observations[(head + bucket->observation_index - 1U) %
                    SSH_DETECTION_CAPACITY].username, item->username) == 0) {
                if (bucket->weight <= SSH_DETECTION_DISTRIBUTED_SPRAY_PER_ACCOUNT_MAX) {
                    if (item->weight > SSH_DETECTION_DISTRIBUTED_SPRAY_PER_ACCOUNT_MAX - bucket->weight)
                        bucket->weight = SSH_DETECTION_DISTRIBUTED_SPRAY_PER_ACCOUNT_MAX + 1U;
                    else
                        bucket->weight += item->weight;
                }
                break;
            }
            slot = (slot + 1U) & (SPRAY_HASH_CAPACITY - 1U);
        }
    }
    for (i = 0; i < SPRAY_HASH_CAPACITY; ++i)
        if (buckets[i].observation_index != 0 &&
            buckets[i].weight > metrics.maximum_account_attempts)
            metrics.maximum_account_attempts = buckets[i].weight;

    memset(buckets, 0, sizeof(buckets));
    for (i = 0; i < count; ++i) {
        const struct auth_observation *item =
            &observations[(head + i) % SSH_DETECTION_CAPACITY];
        unsigned int slot, probes;
        if (item->username[0] == '\0')
            continue;
        slot = address_hash(item->address) & (SPRAY_HASH_CAPACITY - 1U);
        for (probes = 0; probes < SPRAY_HASH_CAPACITY; ++probes) {
            struct spray_bucket *bucket = &buckets[slot];
            if (bucket->observation_index == 0) {
                bucket->observation_index = (uint16_t)(i + 1U);
                bucket->weight = item->weight > SSH_DETECTION_DISTRIBUTED_SPRAY_PER_SOURCE_MAX ?
                    SSH_DETECTION_DISTRIBUTED_SPRAY_PER_SOURCE_MAX + 1U : item->weight;
                ++metrics.distinct_sources;
                break;
            }
            if (strcmp(observations[(head + bucket->observation_index - 1U) %
                    SSH_DETECTION_CAPACITY].address, item->address) == 0) {
                if (bucket->weight <= SSH_DETECTION_DISTRIBUTED_SPRAY_PER_SOURCE_MAX) {
                    if (item->weight > SSH_DETECTION_DISTRIBUTED_SPRAY_PER_SOURCE_MAX - bucket->weight)
                        bucket->weight = SSH_DETECTION_DISTRIBUTED_SPRAY_PER_SOURCE_MAX + 1U;
                    else
                        bucket->weight += item->weight;
                }
                break;
            }
            slot = (slot + 1U) & (SPRAY_HASH_CAPACITY - 1U);
        }
    }
    for (i = 0; i < SPRAY_HASH_CAPACITY; ++i)
        if (buckets[i].observation_index != 0 &&
            buckets[i].weight > metrics.maximum_source_attempts)
            metrics.maximum_source_attempts = buckets[i].weight;
    return metrics;
}

static int
is_distributed_password_spray(const struct distributed_spray_metrics *metrics)
{
    return metrics->total_attempts >= SSH_DETECTION_DISTRIBUTED_SPRAY_ATTEMPT_THRESHOLD &&
        metrics->distinct_accounts >= SSH_DETECTION_DISTRIBUTED_SPRAY_ACCOUNT_THRESHOLD &&
        metrics->distinct_sources >= SSH_DETECTION_DISTRIBUTED_SPRAY_SOURCE_THRESHOLD &&
        metrics->maximum_account_attempts <= SSH_DETECTION_DISTRIBUTED_SPRAY_PER_ACCOUNT_MAX &&
        metrics->maximum_source_attempts <= SSH_DETECTION_DISTRIBUTED_SPRAY_PER_SOURCE_MAX;
}

static int
is_distributed_brute_force(const struct distributed_metrics *metrics)
{
    return metrics->total_attempts >=
            SSH_DETECTION_DISTRIBUTED_ATTEMPT_THRESHOLD &&
        metrics->distinct_sources >=
            SSH_DETECTION_DISTRIBUTED_SOURCE_THRESHOLD &&
        metrics->maximum_source_attempts <=
            SSH_DETECTION_DISTRIBUTED_PER_SOURCE_MAX;
}

static void
safe_username_label(const char *username, char *output, size_t output_size)
{
    size_t i;

    if (!output || output_size == 0)
        return;
    output[0] = '\0';
    if (!username)
        return;

    for (i = 0; i + 1U < output_size && username[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char)username[i];

        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' ||
            ch == '.' || ch == '@')
            output[i] = (char)ch;
        else
            output[i] = '_';
    }
    output[i] = '\0';
}

static int
is_password_spray(const struct spray_metrics *metrics)
{
    return metrics->total_attempts >= SSH_DETECTION_SPRAY_ATTEMPT_THRESHOLD &&
        metrics->distinct_accounts >= SSH_DETECTION_SPRAY_ACCOUNT_THRESHOLD &&
        metrics->maximum_account_attempts <=
            SSH_DETECTION_SPRAY_PER_ACCOUNT_MAX;
}

void
ssh_detection_process_at(const struct ssh_event *event, uint64_t now_ns)
{
    unsigned long long previous, current;
    struct spray_metrics spray_before, spray_after;
    struct distributed_metrics distributed_before, distributed_after;
    struct distributed_spray_metrics distributed_spray_before, distributed_spray_after;
    struct spray_metrics invalid_enum_before, invalid_enum_after;
    unsigned int weight;
    unsigned int tail;
    char normalized_address[SSH_EVENT_IP_MAX];
    char normalized_username[SSH_EVENT_USER_MAX];
    char safe_account[SSH_EVENT_USER_MAX];
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
        !canonicalize_address(event->address, normalized_address,
                              sizeof(normalized_address)))
        return;

    weight = event->is_repetition_summary ? event->repetition_count : 1U;
    if (weight == 0)
        return;

    normalized_username[0] = '\0';
    if (event->has_username && event->username[0] != '\0' &&
        memchr(event->username, '\0', sizeof(event->username)) != NULL)
        (void)snprintf(normalized_username, sizeof(normalized_username),
                       "%s", event->username);

    increment_saturated(&detection_stats.auth_failures_observed);

    if (count == SSH_DETECTION_CAPACITY) {
        memset(&observations[head], 0, sizeof(observations[head]));
        head = (head + 1U) % SSH_DETECTION_CAPACITY;
        --count;
        increment_saturated(&detection_stats.capacity_evictions);
        degraded_until_ns = now_ns > UINT64_MAX - WINDOW_NS ?
            UINT64_MAX : now_ns + WINDOW_NS;
    }

    /* Evaluate the pre-event state after any capacity eviction. */
    previous = normalized_username[0] != '\0' ?
        count_source_user_failures(normalized_address, normalized_username) : 0;
    spray_before = get_spray_metrics(normalized_address);
    distributed_before = normalized_username[0] != '\0' ?
        get_distributed_metrics(normalized_username) :
        (struct distributed_metrics){0, 0, 0};
    invalid_enum_before = get_invalid_user_metrics(normalized_address);
    distributed_spray_before = normalized_username[0] != '\0' ?
        get_distributed_spray_metrics() :
        (struct distributed_spray_metrics){0, 0, 0, 0, 0};

    tail = (head + count) % SSH_DETECTION_CAPACITY;
    slot = &observations[tail];
    memset(slot, 0, sizeof(*slot));
    slot->observed_ns = now_ns;
    slot->weight = weight;
    slot->invalid_user = event->invalid_user != 0;
    (void)snprintf(slot->address, sizeof(slot->address), "%s", normalized_address);
    (void)snprintf(slot->username, sizeof(slot->username), "%s", normalized_username);
    ++count;
    detection_stats.active_observations = count;
    detection_stats.partial_visibility =
        degraded_until_ns != 0 && now_ns < degraded_until_ns;

    if (normalized_username[0] != '\0') {
        current = count_source_user_failures(normalized_address, normalized_username);
        if (previous < SSH_DETECTION_BRUTE_FORCE_THRESHOLD &&
            current >= SSH_DETECTION_BRUTE_FORCE_THRESHOLD) {
            increment_saturated(&detection_stats.brute_force_findings);
            safe_username_label(normalized_username, safe_account,
                                sizeof(safe_account));
            logger_log("SSH_DETECTION",
                "rule=ssh.bruteforce.source_account address=%s account=%s failures=%llu window_seconds=%u threshold=%u confidence=%s evidence=failed_password_records",
                normalized_address, safe_account, current,
                SSH_DETECTION_WINDOW_SECONDS, SSH_DETECTION_BRUTE_FORCE_THRESHOLD,
                detection_stats.partial_visibility ? "reduced" : "moderate");
        }
    }

    invalid_enum_after = get_invalid_user_metrics(normalized_address);
    if (!is_invalid_account_enumeration(&invalid_enum_before) &&
        is_invalid_account_enumeration(&invalid_enum_after)) {
        increment_saturated(&detection_stats.invalid_account_enumeration_findings);
        logger_log("SSH_DETECTION",
            "rule=ssh.account.enumeration.invalid address=%s failures=%llu distinct_invalid_accounts=%u max_per_account=%llu window_seconds=%u attempt_threshold=%u account_threshold=%u per_account_max=%u confidence=%s evidence=failed_password_invalid_user_records",
            normalized_address, invalid_enum_after.total_attempts,
            invalid_enum_after.distinct_accounts, invalid_enum_after.maximum_account_attempts,
            SSH_DETECTION_WINDOW_SECONDS, SSH_DETECTION_INVALID_ENUM_ATTEMPT_THRESHOLD,
            SSH_DETECTION_INVALID_ENUM_ACCOUNT_THRESHOLD,
            SSH_DETECTION_INVALID_ENUM_PER_ACCOUNT_MAX,
            detection_stats.partial_visibility ? "reduced" : "moderate");
    }

    distributed_spray_after = normalized_username[0] != '\0' ?
        get_distributed_spray_metrics() :
        (struct distributed_spray_metrics){0, 0, 0, 0, 0};
    if (normalized_username[0] != '\0' &&
        !is_distributed_password_spray(&distributed_spray_before) &&
        is_distributed_password_spray(&distributed_spray_after)) {
        increment_saturated(&detection_stats.distributed_password_spray_findings);
        logger_log("SSH_DETECTION",
            "rule=ssh.password_spray.distributed failures=%llu distinct_accounts=%u distinct_sources=%u max_per_account=%u max_per_source=%u window_seconds=%u confidence=%s evidence=failed_password_records",
            distributed_spray_after.total_attempts, distributed_spray_after.distinct_accounts,
            distributed_spray_after.distinct_sources, distributed_spray_after.maximum_account_attempts,
            distributed_spray_after.maximum_source_attempts, SSH_DETECTION_WINDOW_SECONDS,
            detection_stats.partial_visibility ? "reduced" : "moderate");
    }

    spray_after = get_spray_metrics(normalized_address);
    if (!is_password_spray(&spray_before) && is_password_spray(&spray_after)) {
        increment_saturated(&detection_stats.password_spray_findings);
        logger_log("SSH_DETECTION",
            "rule=ssh.password_spray.source address=%s failures=%llu distinct_accounts=%u max_per_account=%llu window_seconds=%u attempt_threshold=%u account_threshold=%u per_account_max=%u confidence=%s evidence=failed_password_records",
            normalized_address, spray_after.total_attempts,
            spray_after.distinct_accounts, spray_after.maximum_account_attempts,
            SSH_DETECTION_WINDOW_SECONDS, SSH_DETECTION_SPRAY_ATTEMPT_THRESHOLD,
            SSH_DETECTION_SPRAY_ACCOUNT_THRESHOLD,
            SSH_DETECTION_SPRAY_PER_ACCOUNT_MAX,
            detection_stats.partial_visibility ? "reduced" : "moderate");
    }

    if (normalized_username[0] != '\0') {
        distributed_after = get_distributed_metrics(normalized_username);
        if (!is_distributed_brute_force(&distributed_before) &&
            is_distributed_brute_force(&distributed_after)) {
            increment_saturated(
                &detection_stats.distributed_brute_force_findings);
            safe_username_label(normalized_username, safe_account,
                                sizeof(safe_account));
            logger_log("SSH_DETECTION",
                "rule=ssh.bruteforce.distributed account=%s failures=%llu distinct_sources=%u max_per_source=%u window_seconds=%u attempt_threshold=%u source_threshold=%u per_source_max=%u confidence=%s evidence=failed_password_records",
                safe_account, distributed_after.total_attempts,
                distributed_after.distinct_sources,
                distributed_after.maximum_source_attempts,
                SSH_DETECTION_WINDOW_SECONDS,
                SSH_DETECTION_DISTRIBUTED_ATTEMPT_THRESHOLD,
                SSH_DETECTION_DISTRIBUTED_SOURCE_THRESHOLD,
                SSH_DETECTION_DISTRIBUTED_PER_SOURCE_MAX,
                detection_stats.partial_visibility ? "reduced" : "moderate");
        }
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
ssh_detection_get_stats_at(struct ssh_detection_stats *stats, uint64_t now_ns)
{
    if (!stats)
        return;
    if (now_ns < last_now_ns)
        now_ns = last_now_ns;
    last_now_ns = now_ns;
    expire_observations(now_ns);
    *stats = detection_stats;
}

void
ssh_detection_get_stats(struct ssh_detection_stats *stats)
{
    struct timespec ts;

    if (!stats)
        return;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        *stats = detection_stats;
        stats->active_observations = count;
        return;
    }
    ssh_detection_get_stats_at(stats,
        (uint64_t)ts.tv_sec * NS_PER_SECOND + (uint64_t)ts.tv_nsec);
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
