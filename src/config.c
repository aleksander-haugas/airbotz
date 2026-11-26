#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
static char *trim(char *s) {
    char *e;
    while (isspace((unsigned char)*s)) s++;
    e=s+strlen(s);
    while (e>s && isspace((unsigned char)e[-1])) *--e='\\0';
    return s;
}
int config_load(const char *path, struct ab_config *c) {
    FILE *f; char line[1024]; unsigned n=0;
    if (!path || !c) return -1;
    memset(c,0,sizeof(*c));
    snprintf(c->ssh_log,sizeof(c->ssh_log),"/var/log/auth.log");
    snprintf(c->log_file,sizeof(c->log_file),"/var/log/airbotz.log");
    snprintf(c->pf_table,sizeof(c->pf_table),"airbotz_block");
    c->poll_interval=1; c->enable_pf=1;
    f=fopen(path,"r"); if (!f) return -1;
    while (fgets(line,sizeof(line),f)) {
        char *p=trim(line), *eq, *k, *v; n++;
        if (!*p || *p=='#') continue;
        eq=strchr(p,'='); if (!eq) { fclose(f); return -1; }
        *eq='\\0'; k=trim(p); v=trim(eq+1);
        if (!strcmp(k,"ssh_log")) snprintf(c->ssh_log,sizeof(c->ssh_log),"%s",v);
        else if (!strcmp(k,"log_file")) snprintf(c->log_file,sizeof(c->log_file),"%s",v);
        else if (!strcmp(k,"pf_table")) {
            if (strlen(v)>=sizeof(c->pf_table)) { fclose(f); return -1; }
            snprintf(c->pf_table,sizeof(c->pf_table),"%s",v);
        } else if (!strcmp(k,"poll_interval")) {
            char *end; unsigned long x=strtoul(v,&end,10);
            if (*end || x<1 || x>60) { fclose(f); return -1; }
            c->poll_interval=(unsigned)x;
        } else if (!strcmp(k,"enable_pf")) {
            if (!strcmp(v,"true")) c->enable_pf=1;
            else if (!strcmp(v,"false")) c->enable_pf=0;
            else { fclose(f); return -1; }
        } else { fclose(f); return -1; }
    }
    (void)n; fclose(f);
    if (!c->ssh_log[0] || !c->log_file[0] || !c->pf_table[0]) return -1;
    return 0;
}
