#include "core.h"
#include "logger.h"
#include "pf.h"
#include "ssh.h"
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
static struct ab_config cfg;
static volatile sig_atomic_t stopping;
static void on_signal(int sig) { (void)sig; stopping=1; }
int core_init(const char *path) {
    if (config_load(path,&cfg)!=0) return -1;
    if (logger_init(cfg.log_file)!=0) return -1;
    if (cfg.enable_pf && pf_init(cfg.pf_table)!=0) { logger_log("ERROR","Invalid PF table name"); return -1; }
    if (ssh_init(cfg.ssh_log)!=0) { logger_log("ERROR","Cannot open SSH log %s",cfg.ssh_log); return -1; }
    signal(SIGINT,on_signal); signal(SIGTERM,on_signal);
    logger_log("INFO","AirBotz core initialized; automatic blocking is disabled");
    return 0;
}
int core_run(void) {
    while (!stopping) { ssh_process(); sleep(cfg.poll_interval); }
    return 0;
}
void core_shutdown(void) {
    ssh_shutdown(); pf_shutdown();
    logger_log("INFO","AirBotz stopped"); logger_close();
}
