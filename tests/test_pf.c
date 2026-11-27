#include "pf.h"
#include "logger.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>


static void write_script(const char *path, const char *body) {
    FILE *file = fopen(path, "w");
    assert(file != NULL);
    assert(fputs("#!/bin/sh\n", file) >= 0);
    assert(fputs(body, file) >= 0);
    assert(fclose(file) == 0);
    assert(chmod(path, 0700) == 0);
}

static int log_contains(const char *path, const char *needle) {
    char buffer[8192];
    size_t used;
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    used = fread(buffer, 1, sizeof(buffer) - 1, file);
    buffer[used] = '\0';
    fclose(file);
    return strstr(buffer, needle) != NULL;
}

static void test_pfctl_failures(void) {
    char script[128], log_path[128];
    char entries[2][PF_IP_LEN];
    size_t count = 0;
    int n;

    n = snprintf(script, sizeof(script), "/tmp/airbotz-pfctl-%ld.sh",
                 (long)getpid());
    assert(n > 0 && (size_t)n < sizeof(script));
    n = snprintf(log_path, sizeof(log_path), "/tmp/airbotz-pf-log-%ld",
                 (long)getpid());
    assert(n > 0 && (size_t)n < sizeof(log_path));
    assert(logger_init(log_path) == 0);
    assert(pf_init("airbotz_test_temp", "airbotz_test_perm") == 0);

    write_script(script, "exit 7\n");
    pf_test_set_command_path(script);
    assert(pf_temp_add("192.0.2.77") == -1);
    assert(log_contains(log_path, "exit status 7"));

    write_script(script, "kill -TERM \"$$\"\n");
    assert(pf_temp_add("192.0.2.77") == -1);
    assert(log_contains(log_path, "terminated by signal"));

    write_script(script,
        "dd if=/dev/zero bs=262145 count=1 2>/dev/null\n");
    assert(pf_temp_snapshot(entries, 2, &count) == -1);
    assert(log_contains(log_path, "exceeded 256 KiB limit"));

    write_script(script, "printf '192.0.2.77\\n'\n");
    assert(pf_temp_snapshot(entries, 2, &count) == 0);
    assert(count == 1 && strcmp(entries[0], "192.0.2.77") == 0);

    pf_test_set_command_path("/tmp/airbotz-pfctl-does-not-exist");
    assert(pf_temp_add("192.0.2.77") == -1);
    assert(log_contains(log_path, "exit status 127"));

    pf_shutdown();
    pf_test_set_command_path(NULL);
    logger_close();
    assert(unlink(script) == 0);
    assert(unlink(log_path) == 0);
}

int main(void) {
    char entries[4][PF_IP_LEN];
    size_t count = 99;
    int enabled = -1;
    const char status_enabled[] = "Status: Enabled for 0 days 00:45:07\tDebug: Urgent\n";
    const char status_disabled[] = "Status: Disabled\n";
    const char status_bad[] = "PF is not available\n";
    const char status_duplicate[] = "Status: Enabled\nStatus: Disabled\n";
    const char valid[] = "192.0.2.10\n2001:db8::10\n";
    const char crlf[] = "192.0.2.11\r\n";
    const char duplicate[] = "192.0.2.10\n192.0.2.10\n";
    const char malformed[] = "192.0.2.999\n";
    const char unterminated[] = "192.0.2.12";
    const char blank[] = "\n";
    const char binary[] = {'1', '9', '2', '.', '0', '.', '2', '.', '1', '3',
                           '\0', '\n'};

    assert(pf_parse_status_output(status_enabled,
                                   sizeof(status_enabled) - 1,
                                   &enabled) == 0);
    assert(enabled == 1);
    assert(pf_parse_status_output(status_disabled,
                                   sizeof(status_disabled) - 1,
                                   &enabled) == 0);
    assert(enabled == 0);
    assert(pf_parse_status_output("Status: EnabledX\n",
                                   sizeof("Status: EnabledX\n") - 1,
                                   &enabled) == -1);
    assert(pf_parse_status_output(status_bad, sizeof(status_bad) - 1,
                                   &enabled) == -1);
    assert(pf_parse_status_output(status_duplicate,
                                   sizeof(status_duplicate) - 1,
                                   &enabled) == -1);
    assert(pf_parse_status_output(NULL, 0, &enabled) == -1);

    assert(pf_valid_address("192.0.2.10"));
    assert(pf_valid_address("2001:db8::10"));
    assert(!pf_valid_address("not-an-ip"));
    assert(!pf_valid_address("192.0.2.999"));
    assert(!pf_valid_address(""));

    assert(pf_parse_table_output(NULL, 0, entries, 4, &count) == 0);
    assert(count == 0);
    assert(pf_parse_table_output(valid, sizeof(valid) - 1,
                                 entries, 4, &count) == 0);
    assert(count == 2);
    assert(strcmp(entries[0], "192.0.2.10") == 0);
    assert(strcmp(entries[1], "2001:db8::10") == 0);

    assert(pf_parse_table_output(crlf, sizeof(crlf) - 1,
                                 entries, 4, &count) == 0);
    assert(count == 1 && strcmp(entries[0], "192.0.2.11") == 0);
    assert(pf_parse_table_output(duplicate, sizeof(duplicate) - 1,
                                 entries, 4, &count) == -1);
    assert(pf_parse_table_output(malformed, sizeof(malformed) - 1,
                                 entries, 4, &count) == -1);
    assert(pf_parse_table_output(unterminated, sizeof(unterminated) - 1,
                                 entries, 4, &count) == -1);
    assert(pf_parse_table_output(blank, sizeof(blank) - 1,
                                 entries, 4, &count) == -1);
    assert(pf_parse_table_output(binary, sizeof(binary),
                                 entries, 4, &count) == -1);
    assert(pf_parse_table_output(valid, sizeof(valid) - 1,
                                 entries, 1, &count) == -1);
    assert(pf_parse_table_output(valid, sizeof(valid) - 1,
                                 entries, 0, &count) == -1);

    assert(pf_init("airbotz_temp", "airbotz_perm") == 0);
    assert(pf_init("same_table", "same_table") == -1);
    assert(pf_init("bad-name", "airbotz_perm") == -1);

    pf_shutdown();
    test_pfctl_failures();
    return 0;
}
