#include "ssh_detection.h"
#include "logger.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SECOND UINT64_C(1000000000)

static struct ssh_event
failure(const char *address, const char *username)
{
    struct ssh_event event;

    memset(&event, 0, sizeof(event));
    event.type = SSH_EVENT_FAILED_PASSWORD;
    event.has_address = 1;
    (void)snprintf(event.address, sizeof(event.address), "%s", address);
    event.has_username = 1;
    (void)snprintf(event.username, sizeof(event.username), "%s", username);
    return event;
}

static unsigned int
count_spray_findings(const char *path)
{
    FILE *file = fopen(path, "r");
    char line[1024];
    unsigned int found = 0;

    assert(file != NULL);
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, "rule=ssh.password_spray.source"))
            ++found;
    }
    fclose(file);
    return found;
}

static unsigned int
count_distributed_findings(const char *path)
{
    FILE *file = fopen(path, "r");
    char line[1024];
    unsigned int found = 0;

    assert(file != NULL);
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, "rule=ssh.bruteforce.distributed"))
            ++found;
    }
    fclose(file);
    return found;
}

static unsigned int
count_invalid_enum_findings(const char *path)
{
    FILE *file = fopen(path, "r");
    char line[1024];
    unsigned int found = 0;
    assert(file != NULL);
    while (fgets(line, sizeof(line), file) != NULL)
        if (strstr(line, "rule=ssh.account.enumeration.invalid"))
            ++found;
    fclose(file);
    return found;
}

static unsigned int
count_distributed_spray_findings(const char *path)
{
    FILE *file = fopen(path, "r");
    char line[1024];
    unsigned int found = 0;
    assert(file != NULL);
    while (fgets(line, sizeof(line), file) != NULL)
        if (strstr(line, "rule=ssh.password_spray.distributed"))
            ++found;
    fclose(file);
    return found;
}

static unsigned int
count_findings(const char *path)
{
    FILE *file = fopen(path, "r");
    char line[1024];
    unsigned int found = 0;

    assert(file != NULL);
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, "rule=ssh.bruteforce.source_account"))
            ++found;
    }
    fclose(file);
    return found;
}

int
main(void)
{
    char path[] = "/tmp/airbotz-ssh-detect.XXXXXX";
    int fd = mkstemp(path);
    struct ssh_event event;
    struct ssh_detection_stats stats;
    unsigned int i;

    assert(fd >= 0);
    close(fd);
    assert(logger_init(path) == 0);
    ssh_detection_reset();

    /* Seven failures are below threshold; the eighth crosses it once. */
    for (i = 0; i < 7; ++i) {
        event = failure("192.0.2.10", "root");
        ssh_detection_process_at(&event, (uint64_t)(10 + i) * SECOND);
    }
    assert(count_findings(path) == 0);
    event = failure("192.0.2.10", "root");
    ssh_detection_process_at(&event, 17 * SECOND);
    assert(count_findings(path) == 1);
    ssh_detection_process_at(&event, 18 * SECOND);
    assert(count_findings(path) == 1);

    /* A different source cannot contribute to the first source's threshold. */
    ssh_detection_reset();
    for (i = 0; i < 7; ++i) {
        event = failure(i % 2 ? "192.0.2.20" : "192.0.2.21", "root");
        ssh_detection_process_at(&event, (uint64_t)(30 + i) * SECOND);
    }
    assert(count_findings(path) == 1);

    /* Expired observations do not contribute to a later window. */
    ssh_detection_reset();
    for (i = 0; i < 7; ++i) {
        event = failure("192.0.2.30", "root");
        ssh_detection_process_at(&event, 100 * SECOND);
    }
    event = failure("192.0.2.30", "root");
    ssh_detection_process_at(&event, 401 * SECOND);
    assert(count_findings(path) == 1);

    /* Repetition summary contributes N additional copies, not N+1. */
    ssh_detection_reset();
    for (i = 0; i < 7; ++i) {
        event = failure("192.0.2.40", "root");
        ssh_detection_process_at(&event, (uint64_t)(500 + i) * SECOND);
    }
    event = failure("192.0.2.40", "root");
    event.is_repetition_summary = 1;
    event.repetition_count = 1;
    ssh_detection_process_at(&event, 507 * SECOND);
    assert(count_findings(path) == 2);

    /* Equivalent IPv6 spellings share one canonical source key. */
    ssh_detection_reset();
    for (i = 0; i < 7; ++i) {
        event = failure(i % 2 ? "2001:db8::1" :
                        "2001:0db8:0:0:0:0:0:1", "root");
        ssh_detection_process_at(&event, (uint64_t)(800 + i) * SECOND);
    }
    assert(count_findings(path) == 2);
    event = failure("2001:0db8:0:0:0:0:0:1", "root");
    ssh_detection_process_at(&event, 807 * SECOND);
    assert(count_findings(path) == 3);

    /* Broad low-rate account targeting is a spray, not brute force. */
    ssh_detection_reset();
    for (i = 0; i < 7; ++i) {
        char username[SSH_EVENT_USER_MAX];
        unsigned int account = i < 6 ? i / 2U : 3U;
        (void)snprintf(username, sizeof(username), "account%u", account);
        event = failure("192.0.2.70", username);
        ssh_detection_process_at(&event, (uint64_t)(900 + i) * SECOND);
    }
    assert(count_spray_findings(path) == 0);
    ssh_detection_get_stats_at(&stats, 906 * SECOND);
    assert(stats.brute_force_findings == 0);
    event = failure("192.0.2.70", "account4");
    ssh_detection_process_at(&event, 907 * SECOND);
    assert(count_spray_findings(path) == 1);
    ssh_detection_get_stats_at(&stats, 907 * SECOND);
    assert(stats.password_spray_findings == 1);
    assert(stats.brute_force_findings == 0);

    /* Repeated targeting of one account is brute force, not password spray. */
    ssh_detection_reset();
    for (i = 0; i < 8; ++i) {
        event = failure("192.0.2.71", "single-account");
        ssh_detection_process_at(&event, (uint64_t)(920 + i) * SECOND);
    }
    ssh_detection_get_stats_at(&stats, 927 * SECOND);
    assert(stats.brute_force_findings == 1);
    assert(stats.password_spray_findings == 0);

    /* Distributed brute force: one account, many sources, low rate per source. */
    ssh_detection_reset();
    for (i = 0; i < 8; ++i) {
        char address[SSH_EVENT_IP_MAX];
        (void)snprintf(address, sizeof(address), "198.51.100.%u",
                       (i / 2U) + 10U);
        event = failure(address, "shared-account");
        ssh_detection_process_at(&event, (uint64_t)(940 + i) * SECOND);
    }
    assert(count_distributed_findings(path) == 0);
    event = failure("198.51.100.15", "shared-account");
    ssh_detection_process_at(&event, 948 * SECOND);
    assert(count_distributed_findings(path) == 1);
    ssh_detection_get_stats_at(&stats, 948 * SECOND);
    assert(stats.distributed_brute_force_findings == 1);
    assert(stats.brute_force_findings == 0);
    assert(stats.password_spray_findings == 0);

    /* A single source repeatedly attacking one account is not distributed. */
    ssh_detection_reset();
    for (i = 0; i < 8; ++i) {
        event = failure("198.51.100.20", "single-source-account");
        ssh_detection_process_at(&event, (uint64_t)(960 + i) * SECOND);
    }
    ssh_detection_get_stats_at(&stats, 967 * SECOND);
    assert(stats.distributed_brute_force_findings == 0);

    /* Distributed password spray: many sources, many accounts, low per-key rates. */
    ssh_detection_reset();
    for (i = 0; i < 7; ++i) {
        char address[SSH_EVENT_IP_MAX];
        char username[SSH_EVENT_USER_MAX];
        (void)snprintf(address, sizeof(address), "203.0.113.%u", 10U + i % 5U);
        (void)snprintf(username, sizeof(username), "target%u", i % 5U);
        event = failure(address, username);
        ssh_detection_process_at(&event, (uint64_t)(980 + i) * SECOND);
    }
    assert(count_distributed_spray_findings(path) == 0);
    event = failure("203.0.113.12", "target2");
    ssh_detection_process_at(&event, 987 * SECOND);
    assert(count_distributed_spray_findings(path) == 1);
    ssh_detection_get_stats_at(&stats, 987 * SECOND);
    assert(stats.distributed_password_spray_findings == 1);
    assert(stats.distributed_brute_force_findings == 0);
    assert(stats.password_spray_findings == 0);
    assert(stats.brute_force_findings == 0);

    /* A single source spraying many accounts is not distributed spraying. */
    ssh_detection_reset();
    for (i = 0; i < 8; ++i) {
        char username[SSH_EVENT_USER_MAX];
        (void)snprintf(username, sizeof(username), "single%u", i);
        event = failure("203.0.113.40", username);
        ssh_detection_process_at(&event, (uint64_t)(1000 + i) * SECOND);
    }
    ssh_detection_get_stats_at(&stats, 1007 * SECOND);
    assert(stats.distributed_password_spray_findings == 0);

    /* Malformed address text must never become a source key. */
    ssh_detection_reset();
    event = failure("not-an-ip-address", "root");
    ssh_detection_process_at(&event, 850 * SECOND);
    ssh_detection_get_stats_at(&stats, 850 * SECOND);
    assert(stats.auth_failures_observed == 0);

    /* Invalid-account enumeration requires several distinct invalid names. */
    ssh_detection_reset();
    for (i = 0; i < 8; ++i) {
        char username[SSH_EVENT_USER_MAX];
        (void)snprintf(username, sizeof(username), "ghost%u", i < 6 ? i / 2U : i - 3U);
        event = failure("192.0.2.77", username);
        event.invalid_user = 1;
        ssh_detection_process_at(&event, (uint64_t)(580 + i) * SECOND);
    }
    assert(count_invalid_enum_findings(path) == 1);
    ssh_detection_get_stats_at(&stats, 587 * SECOND);
    assert(stats.invalid_account_enumeration_findings == 1);

    /* Repeated guesses against one invalid name are not enumeration. */
    ssh_detection_reset();
    for (i = 0; i < 8; ++i) {
        event = failure("192.0.2.78", "ghost");
        event.invalid_user = 1;
        ssh_detection_process_at(&event, (uint64_t)(590 + i) * SECOND);
    }
    assert(count_invalid_enum_findings(path) == 1);
    ssh_detection_get_stats_at(&stats, 597 * SECOND);
    assert(stats.invalid_account_enumeration_findings == 0);

    /* Valid-account spray records do not satisfy invalid-account enumeration. */
    ssh_detection_reset();
    for (i = 0; i < 8; ++i) {
        char username[SSH_EVENT_USER_MAX];
        (void)snprintf(username, sizeof(username), "known%u", i);
        event = failure("192.0.2.79", username);
        ssh_detection_process_at(&event, (uint64_t)(600 + i) * SECOND);
    }
    ssh_detection_get_stats_at(&stats, 607 * SECOND);
    assert(stats.invalid_account_enumeration_findings == 0);

    /* Other event families and missing source addresses are not attempts. */
    ssh_detection_reset();
    event = failure("192.0.2.50", "root");
    event.type = SSH_EVENT_PAM_AUTH_FAILURE;
    ssh_detection_process_at(&event, 600 * SECOND);
    event = failure("192.0.2.50", "root");
    event.has_address = 0;
    ssh_detection_process_at(&event, 601 * SECOND);
    ssh_detection_get_stats_at(&stats, 601 * SECOND);
    assert(stats.auth_failures_observed == 0);

    /* The fixed ring never exceeds capacity; overflow is visible. */
    ssh_detection_reset();
    for (i = 0; i < SSH_DETECTION_CAPACITY + 1U; ++i) {
        char address[SSH_EVENT_IP_MAX];
        (void)snprintf(address, sizeof(address), "192.0.2.%u", (i % 250U) + 1U);
        event = failure(address, "root");
        ssh_detection_process_at(&event, 1000 * SECOND + (uint64_t)i);
    }
    ssh_detection_get_stats_at(&stats, 1000 * SECOND + SSH_DETECTION_CAPACITY + 1U);
    assert(stats.active_observations == SSH_DETECTION_CAPACITY);
    assert(stats.capacity_evictions == 1);
    assert(stats.partial_visibility == 1);

    /* Monotonic time regression is clamped, not used to extend/reset windows. */
    ssh_detection_reset();
    event = failure("192.0.2.60", "root");
    ssh_detection_process_at(&event, 2000 * SECOND);
    ssh_detection_process_at(&event, 1990 * SECOND);
    ssh_detection_get_stats_at(&stats, 2000 * SECOND);
    assert(stats.active_observations == 2);

    logger_close();
    assert(unlink(path) == 0);
    puts("PASS: SSH brute-force, password-spray and invalid-account enumeration correlation, windows, thresholds, expiry, summaries and capacity telemetry");
    return 0;
}
