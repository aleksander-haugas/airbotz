#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static char *trim(char *s) {
    char *e;
    while (isspace((unsigned char)*s)) s++;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

int config_load(const char *path, struct ab_config *c) {
    FILE *f;
    char line[1024];

    if (!path || !c) return -1;
    memset(c, 0, sizeof(*c));
    snprintf(c->ssh_log, sizeof(c->ssh_log), "/var/log/auth.log");
    snprintf(c->log_file, sizeof(c->log_file), "/var/log/airbotz.log");
    snprintf(c->pf_temp_table, sizeof(c->pf_temp_table), "airbotz_temp");
    snprintf(c->pf_perm_table, sizeof(c->pf_perm_table), "airbotz_perm");
    c->poll_interval = 1;
    c->enable_pf = 1;

    f = fopen(path, "r");
    if (!f) return -1;

    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line), *eq, *k, *v;
        if (!*p || *p == '#') continue;
        eq = strchr(p, '=');
        if (!eq) { fclose(f); return -1; }
        *eq = '\0';
        k = trim(p);
        v = trim(eq + 1);

        if (!strcmp(k, "ssh_log")) {
            if (strlen(v) >= sizeof(c->ssh_log)) { fclose(f); return -1; }
            snprintf(c->ssh_log, sizeof(c->ssh_log), "%s", v);
        } else if (!strcmp(k, "log_file")) {
            if (strlen(v) >= sizeof(c->log_file)) { fclose(f); return -1; }
            snprintf(c->log_file, sizeof(c->log_file), "%s", v);
        } else if (!strcmp(k, "pf_temp_table")) {
            if (strlen(v) >= sizeof(c->pf_temp_table)) { fclose(f); return -1; }
            snprintf(c->pf_temp_table, sizeof(c->pf_temp_table), "%s", v);
        } else if (!strcmp(k, "pf_perm_table")) {
            if (strlen(v) >= sizeof(c->pf_perm_table)) { fclose(f); return -1; }
            snprintf(c->pf_perm_table, sizeof(c->pf_perm_table), "%s", v);
        } else if (!strcmp(k, "poll_interval")) {
            char *end;
            unsigned long x = strtoul(v, &end, 10);
            if (*end || x < 1 || x > 60) { fclose(f); return -1; }
            c->poll_interval = (unsigned)x;
        } else if (!strcmp(k, "enable_pf")) {
            if (!strcmp(v, "true")) c->enable_pf = 1;
            else if (!strcmp(v, "false")) c->enable_pf = 0;
            else { fclose(f); return -1; }
        } else {
            fclose(f);
            return -1;
        }
    }

    if (ferror(f)) { fclose(f); return -1; }
    fclose(f);
    return c->ssh_log[0] && c->log_file[0] &&
           c->pf_temp_table[0] && c->pf_perm_table[0] ? 0 : -1;
}
