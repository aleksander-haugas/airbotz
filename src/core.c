#include "core.h"
#include "address_manager.h"
#include "logger.h"
#include "pf.h"
#include "ssh.h"
#include "storage.h"

#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

static struct ab_config cfg;
static struct address_manager addresses;
static volatile sig_atomic_t stopping;
static int logger_ready;
static int pf_ready;
static int ssh_ready;

static int pf_temp_add_cb(const char *ip) { return pf_temp_add(ip); }
static int pf_temp_delete_cb(const char *ip) { return pf_temp_delete(ip); }
static int pf_perm_add_cb(const char *ip) { return pf_perm_add(ip); }
static int pf_perm_delete_cb(const char *ip) { return pf_perm_delete(ip); }

static const struct address_manager_ops pf_ops = {
    pf_temp_add_cb, pf_temp_delete_cb, pf_perm_add_cb, pf_perm_delete_cb
};

static void
on_signal(int sig)
{
    (void)sig;
    stopping = 1;
}

int
core_init(const char *path)
{
    struct sigaction action;

    stopping = 0;
    logger_ready = 0;
    pf_ready = 0;
    ssh_ready = 0;

    if (config_load(path, &cfg) != 0)
        return -1;

    if (logger_init(cfg.log_file) != 0)
        return -1;
    logger_ready = 1;

    if (storage_init(cfg.storage_dir) != 0) {
        logger_log("ERROR", "Cannot initialize persistence directory %s",
                   cfg.storage_dir);
        core_shutdown();
        return -1;
    }

    if (cfg.enable_pf) {
        if (pf_init(cfg.pf_temp_table, cfg.pf_perm_table) != 0) {
            logger_log("ERROR", "Invalid or duplicate PF table names");
            core_shutdown();
            return -1;
        }
        pf_ready = 1;
    }

    if (address_manager_init(&addresses, &pf_ops, pf_ready) != 0 ||
        address_manager_restore(&addresses) != 0) {
        logger_log("ERROR", "Cannot initialize or restore managed IP addresses");
        core_shutdown();
        return -1;
    }

    if (ssh_init(cfg.ssh_log) != 0) {
        logger_log("ERROR", "Cannot open SSH log %s", cfg.ssh_log);
        core_shutdown();
        return -1;
    }
    ssh_ready = 1;

    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        logger_log("ERROR", "Cannot install signal handlers");
        core_shutdown();
        return -1;
    }

    logger_log("INFO",
        "Persistence restored: %zu permanent, %zu temporary IPs",
        addresses.permanent_count, addresses.temporary_count);
    logger_log("INFO",
        "AirBotz core initialized; automatic blocking is disabled");
    return 0;
}

int
core_run(void)
{
    while (!stopping) {
        size_t expired = 0;
        ssh_process();
        if (address_manager_expire(&addresses, time(NULL), &expired) != 0)
            logger_log("ERROR", "Could not expire temporary PF addresses");
        else if (expired)
            logger_log("INFO", "Expired %zu temporary IP addresses", expired);
        if (!stopping)
            (void)sleep(cfg.poll_interval);
    }
    return 0;
}

void
core_shutdown(void)
{
    if (ssh_ready) {
        ssh_shutdown();
        ssh_ready = 0;
    }
    if (pf_ready) {
        pf_shutdown();
        pf_ready = 0;
    }
    if (logger_ready) {
        logger_log("INFO", "AirBotz stopped");
        logger_close();
        logger_ready = 0;
    }
}
