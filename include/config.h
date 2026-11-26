#ifndef AIRBOTZ_CONFIG_H
#define AIRBOTZ_CONFIG_H
struct ab_config {
    char ssh_log[512];
    char log_file[512];
    char pf_temp_table[64];
    char pf_perm_table[64];
    unsigned poll_interval;
    int enable_pf;
};
int config_load(const char *path, struct ab_config *cfg);
#endif
