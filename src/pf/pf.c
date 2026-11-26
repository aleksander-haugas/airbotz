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

static char table_name[64];

int pf_valid_address(const char *ip) {
    unsigned char buf[sizeof(struct in6_addr)];
    return ip && (inet_pton(AF_INET, ip, buf) == 1 ||
                  inet_pton(AF_INET6, ip, buf) == 1);
}

static int valid_table(const char *s) {
    size_t i, n;
    if (!s || !(n = strlen(s)) || n >= sizeof(table_name)) return 0;
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

int pf_init(const char *table) {
    if (!valid_table(table)) return -1;
    snprintf(table_name, sizeof(table_name), "%s", table);
    return 0;
}

int pf_status(void) {
    char *const args[] = {"/sbin/pfctl", "-s", "info", NULL};
    return run_pfctl(args);
}

int pf_table_add(const char *ip) {
    char *const args[] = {"/sbin/pfctl", "-t", table_name, "-T", "add",
                          (char *)ip, NULL};
    if (!pf_valid_address(ip) || !table_name[0]) return -1;
    return run_pfctl(args);
}

int pf_table_delete(const char *ip) {
    char *const args[] = {"/sbin/pfctl", "-t", table_name, "-T", "delete",
                          (char *)ip, NULL};
    if (!pf_valid_address(ip) || !table_name[0]) return -1;
    return run_pfctl(args);
}

void pf_shutdown(void) {
    table_name[0] = '\0';
}
