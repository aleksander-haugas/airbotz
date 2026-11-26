#include "pf.h"
#include "logger.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
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

static int run_pfctl(char *const argv[]) {
    pid_t pid = fork();
    int status;
    if (pid < 0) return -1;
    if (pid == 0) {
        execv("/sbin/pfctl", argv);
        _exit(127);
    }
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
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

void pf_shutdown(void) {
    temp_table[0] = '\0';
    perm_table[0] = '\0';
}
