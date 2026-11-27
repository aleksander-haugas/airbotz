#include "pf.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define TEST_IP "192.0.2.10"

static int address_present(const char *table) {
    int output_pipe[2];
    pid_t pid;
    int status;
    char output[256] = {0};
    ssize_t used = 0;

    if (pipe(output_pipe) != 0)
        return -1;

    pid = fork();
    if (pid < 0) {
        close(output_pipe[0]);
        close(output_pipe[1]);
        return -1;
    }
    if (pid == 0) {
        char *const args[] = {
            "/sbin/pfctl", "-t", (char *)table, "-T", "test",
            TEST_IP, NULL
        };
        close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(output_pipe[1], STDERR_FILENO) < 0)
            _exit(126);
        close(output_pipe[1]);
        execv("/sbin/pfctl", args);
        _exit(127);
    }

    close(output_pipe[1]);
    while (used < (ssize_t)sizeof(output) - 1) {
        ssize_t n = read(output_pipe[0], output + used,
                         sizeof(output) - 1 - (size_t)used);
        if (n <= 0)
            break;
        used += n;
    }
    close(output_pipe[0]);

    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
        return -1;

    /*
     * pfctl may return a non-zero exit status when the address is absent.
     * The match count is the authoritative result; only unknown output is
     * treated as an inspection error.
     */
    if (strstr(output, "1/1 addresses match") != NULL)
        return 1;
    if (strstr(output, "0/1 addresses match") != NULL)
        return 0;
    return -1;
}

static int exercise_snapshot(const char *name,
                              int (*snapshot_fn)(char entries[][PF_IP_LEN],
                                                 size_t capacity,
                                                 size_t *count)) {
    char entries[PF_SNAPSHOT_MAX_ENTRIES][PF_IP_LEN];
    size_t count = 0, i;

    if (snapshot_fn(entries, PF_SNAPSHOT_MAX_ENTRIES, &count) != 0) {
        fprintf(stderr, "FAIL: snapshot of %s failed\n", name);
        return -1;
    }
    for (i = 0; i < count; i++) {
        if (!pf_valid_address(entries[i])) {
            fprintf(stderr, "FAIL: snapshot of %s returned invalid address\n",
                    name);
            return -1;
        }
    }
    printf("PASS: snapshot of %s (%zu entr%s)\n", name, count,
           count == 1 ? "y" : "ies");
    return 0;
}

static int exercise_table(const char *name,
                          int (*add_fn)(const char *),
                          int (*delete_fn)(const char *)) {
    int present = address_present(name);

    if (present < 0) {
        fprintf(stderr, "FAIL: could not check %s before test\n", name);
        return -1;
    }
    if (present) {
        fprintf(stderr,
                "SKIP: %s already contains %s; leaving existing entry untouched\n",
                name, TEST_IP);
        return 1;
    }

    printf("Testing %s with %s\n", name, TEST_IP);
    if (add_fn(TEST_IP) != 0) {
        fprintf(stderr, "FAIL: add to %s failed\n", name);
        return -1;
    }
    if (delete_fn(TEST_IP) != 0) {
        fprintf(stderr, "FAIL: delete from %s failed; attempting cleanup\n", name);
        (void)delete_fn(TEST_IP);
        return -1;
    }
    printf("PASS: add/delete on %s\n", name);
    return 0;
}

int main(void) {
    int failed = 0;

    if (geteuid() != 0) {
        fprintf(stderr, "Run this integration test as root.\n");
        return 2;
    }
    if (pf_init("airbotz_temp", "airbotz_perm") != 0) {
        fprintf(stderr, "Could not initialize AirBotz PF table names.\n");
        return 1;
    }
    if (pf_status() != 0) {
        fprintf(stderr, "PF is unavailable or disabled.\n");
        pf_shutdown();
        return 1;
    }

    if (exercise_snapshot("airbotz_temp", pf_temp_snapshot) != 0)
        failed = 1;
    if (exercise_snapshot("airbotz_perm", pf_perm_snapshot) != 0)
        failed = 1;

    /*
     * TEST-NET-1 is documentation-only. Refuse to run against a table
     * that already contains the address, so the test cannot delete a
     * pre-existing entry.
     */
    if (exercise_table("airbotz_temp", pf_temp_add, pf_temp_delete) < 0)
        failed = 1;
    if (exercise_table("airbotz_perm", pf_perm_add, pf_perm_delete) < 0)
        failed = 1;

    pf_shutdown();
    return failed ? 1 : 0;
}
