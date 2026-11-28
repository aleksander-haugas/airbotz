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
count_findings(const char *path)
{
    FILE *file = fopen(path, "r");
    char line[1024];
    unsigned int found = 0;

    assert(file != NULL);
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, "rule=ssh.bruteforce.source"))
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
        event = failure("192.0.2.10", i % 2 ? "root" : "admin");
        ssh_detection_process_at(&event, (uint64_t)(10 + i) * SECOND);
    }
    assert(count_findings(path) == 0);
    event = failure("192.0.2.10", "test");
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
    puts("PASS: SSH bounded brute-force correlation windows, threshold, expiry, summaries and capacity telemetry");
    return 0;
}
