#include "pf.h"
#include "logger.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static char temp_table[64];
static char perm_table[64];

int pf_valid_address(const char *ip) {
    unsigned char buf[sizeof(struct in6_addr)];
    return ip && (inet_pton(AF_INET, ip, buf) == 1 ||
                  inet_pton(AF_INET6, ip, buf) == 1);
}

static int valid_table(const char *s) {
    size_t i, n;
    if (!s || !(n = strlen(s)) || n >= sizeof(temp_table)) return 0;
    for (i = 0; i < n; i++) {
        if (!((s[i] >= 'a' && s[i] <= 'z') ||
              (s[i] >= 'A' && s[i] <= 'Z') ||
              (s[i] >= '0' && s[i] <= '9') || s[i] == '_')) return 0;
    }
    return 1;
}

static void
log_pfctl_failure(char *const argv[], const char *detail)
{
    char command[256];
    size_t used = 0, i;

    command[0] = '\0';
    for (i = 1; argv[i] && used < sizeof(command); i++) {
        int n = snprintf(command + used, sizeof(command) - used,
                         "%s%s", used ? " " : "", argv[i]);
        if (n < 0 || (size_t)n >= sizeof(command) - used)
            break;
        used += (size_t)n;
    }
    logger_log("ERROR", "pfctl %s failed (%s)",
               command[0] ? command : "command", detail);
}

static int
wait_pfctl(pid_t pid, int *status, char *const argv[])
{
    pid_t result;

    do {
        result = waitpid(pid, status, 0);
    } while (result < 0 && errno == EINTR);

    if (result < 0) {
        int saved_errno = errno;
        char detail[128];
        snprintf(detail, sizeof(detail), "waitpid: %s",
                 strerror(saved_errno));
        log_pfctl_failure(argv, detail);
        return -1;
    }
    if (WIFEXITED(*status)) {
        if (WEXITSTATUS(*status) == 0)
            return 0;
        {
            char detail[64];
            snprintf(detail, sizeof(detail), "exit status %d",
                     WEXITSTATUS(*status));
            log_pfctl_failure(argv, detail);
        }
    } else if (WIFSIGNALED(*status)) {
        char detail[64];
        snprintf(detail, sizeof(detail), "terminated by signal %d",
                 WTERMSIG(*status));
        log_pfctl_failure(argv, detail);
    } else {
        log_pfctl_failure(argv, "unexpected child state");
    }
    return -1;
}

static int
run_pfctl(char *const argv[])
{
    pid_t pid = fork();
    int status;

    if (pid < 0) {
        int saved_errno = errno;
        char detail[128];
        snprintf(detail, sizeof(detail), "fork: %s", strerror(saved_errno));
        log_pfctl_failure(argv, detail);
        return -1;
    }
    if (pid == 0) {
        execv("/sbin/pfctl", argv);
        _exit(127);
    }
    return wait_pfctl(pid, &status, argv);
}

static int run_pfctl_capture(char *const argv[], char **output,
                             size_t *output_length) {
    int pipefd[2], read_error = 0, oversized = 0;
    size_t used = 0;
    char *buffer;
    pid_t pid;
    int status;
    char chunk[4096];

    if (!output || !output_length) return -1;
    *output = NULL;
    *output_length = 0;
    buffer = malloc(PF_SNAPSHOT_MAX_BYTES + 1);
    if (!buffer) {
        log_pfctl_failure(argv, "cannot allocate output buffer");
        return -1;
    }
    if (pipe(pipefd) != 0) {
        int saved_errno = errno;
        char detail[128];
        snprintf(detail, sizeof(detail), "pipe: %s", strerror(saved_errno));
        log_pfctl_failure(argv, detail);
        free(buffer);
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        int saved_errno = errno;
        char detail[128];
        snprintf(detail, sizeof(detail), "fork: %s", strerror(saved_errno));
        log_pfctl_failure(argv, detail);
        close(pipefd[0]);
        close(pipefd[1]);
        free(buffer);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(126);
        close(pipefd[1]);
        execv("/sbin/pfctl", argv);
        _exit(127);
    }

    close(pipefd[1]);
    for (;;) {
        ssize_t n = read(pipefd[0], chunk, sizeof(chunk));
        if (n > 0) {
            if ((size_t)n > PF_SNAPSHOT_MAX_BYTES - used) {
                oversized = 1;
            } else if (!oversized) {
                memcpy(buffer + used, chunk, (size_t)n);
                used += (size_t)n;
            }
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        read_error = 1;
        break;
    }
    close(pipefd[0]);
    if (wait_pfctl(pid, &status, argv) != 0) {
        free(buffer);
        return -1;
    }
    if (read_error || oversized) {
        if (read_error)
            log_pfctl_failure(argv, "failed while reading command output");
        else
            log_pfctl_failure(argv, "command output exceeded 256 KiB limit");
        free(buffer);
        return -1;
    }
    buffer[used] = '\0';
    *output = buffer;
    *output_length = used;
    return 0;
}

int pf_parse_table_output(const char *output, size_t length,
                          char entries[][PF_IP_LEN], size_t capacity,
                          size_t *count) {
    size_t pos = 0, used = 0;

    if (!count || (length && !output) || (capacity && !entries) ||
        capacity > PF_SNAPSHOT_MAX_ENTRIES)
        return -1;
    *count = 0;
    if (length == 0) return 0;
    if (output[length - 1] != '\n') return -1;

    while (pos < length) {
        size_t start = pos, n, i;
        char address[PF_IP_LEN];

        while (pos < length && output[pos] != '\n') {
            if (output[pos] == '\0') return -1;
            pos++;
        }
        if (pos == length) return -1;
        n = pos - start;
        pos++;
        if (n && output[start + n - 1] == '\r') n--;
        if (n == 0 || n >= sizeof(address) || used >= capacity)
            return -1;
        memcpy(address, output + start, n);
        address[n] = '\0';
        if (!pf_valid_address(address)) return -1;
        for (i = 0; i < used; i++)
            if (strcmp(entries[i], address) == 0) return -1;
        memcpy(entries[used], address, n + 1);
        used++;
    }
    *count = used;
    return 0;
}

static int table_snapshot(const char *table, char entries[][PF_IP_LEN],
                          size_t capacity, size_t *count) {
    char *const args[] = {"/sbin/pfctl", "-t", (char *)table,
                          "-T", "show", NULL};
    char *output = NULL;
    size_t length = 0;
    int rc;

    if (!valid_table(table) || !count ||
        (capacity && !entries) || capacity > PF_SNAPSHOT_MAX_ENTRIES)
        return -1;
    *count = 0;
    if (run_pfctl_capture(args, &output, &length) != 0)
        return -1;
    rc = pf_parse_table_output(output, length, entries, capacity, count);
    free(output);
    return rc;
}

int pf_init(const char *temporary, const char *permanent) {
    if (!valid_table(temporary) || !valid_table(permanent) ||
        strcmp(temporary, permanent) == 0)
        return -1;

    snprintf(temp_table, sizeof(temp_table), "%s", temporary);
    snprintf(perm_table, sizeof(perm_table), "%s", permanent);
    return 0;
}

int pf_status(void) {
    char *const args[] = {"/sbin/pfctl", "-s", "info", NULL};
    return run_pfctl(args);
}

int pf_parse_status_output(const char *output, size_t length,
                           int *enabled) {
    size_t pos = 0;
    int found = 0, value = 0;

    if (!output || !enabled || length == 0)
        return -1;
    while (pos < length) {
        size_t start = pos, n;
        while (pos < length && output[pos] != '\n') {
            if (output[pos] == '\0')
                return -1;
            pos++;
        }
        n = pos - start;
        if (pos < length)
            pos++;
        if (n && output[start + n - 1] == '\r')
            n--;
        if (n >= sizeof("Status: Enabled") - 1 &&
            memcmp(output + start, "Status: Enabled",
                   sizeof("Status: Enabled") - 1) == 0 &&
            (n == sizeof("Status: Enabled") - 1 ||
             output[start + sizeof("Status: Enabled") - 1] == ' ' ||
             output[start + sizeof("Status: Enabled") - 1] == '\t')) {
            if (found) return -1;
            found = 1;
            value = 1;
        } else if (n >= sizeof("Status: Disabled") - 1 &&
                   memcmp(output + start, "Status: Disabled",
                          sizeof("Status: Disabled") - 1) == 0 &&
                   (n == sizeof("Status: Disabled") - 1 ||
                    output[start + sizeof("Status: Disabled") - 1] == ' ' ||
                    output[start + sizeof("Status: Disabled") - 1] == '\t')) {
            if (found) return -1;
            found = 1;
            value = 0;
        }
    }
    if (!found)
        return -1;
    *enabled = value;
    return 0;
}

int pf_get_status(int *enabled) {
    char *const args[] = {"/sbin/pfctl", "-s", "info", NULL};
    char *output = NULL;
    size_t length = 0;
    int rc;

    if (!enabled)
        return -1;
    if (run_pfctl_capture(args, &output, &length) != 0)
        return -1;
    rc = pf_parse_status_output(output, length, enabled);
    free(output);
    return rc;
}


static int table_operation(const char *table, const char *operation,
                           const char *ip) {
    char *const args[] = {"/sbin/pfctl", "-t", (char *)table, "-T",
                          (char *)operation, (char *)ip, NULL};
    if (!table[0] || !pf_valid_address(ip)) return -1;
    return run_pfctl(args);
}

int pf_temp_add(const char *ip) {
    return table_operation(temp_table, "add", ip);
}

int pf_temp_delete(const char *ip) {
    return table_operation(temp_table, "delete", ip);
}

int pf_perm_add(const char *ip) {
    return table_operation(perm_table, "add", ip);
}

int pf_perm_delete(const char *ip) {
    return table_operation(perm_table, "delete", ip);
}

int pf_temp_snapshot(char entries[][PF_IP_LEN], size_t capacity,
                     size_t *count) {
    return table_snapshot(temp_table, entries, capacity, count);
}

int pf_perm_snapshot(char entries[][PF_IP_LEN], size_t capacity,
                     size_t *count) {
    return table_snapshot(perm_table, entries, capacity, count);
}

void pf_shutdown(void) {
    temp_table[0] = '\0';
    perm_table[0] = '\0';
}
