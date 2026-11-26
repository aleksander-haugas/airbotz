#include "core.h"
#include "logger.h"
#include "pf.h"
#include "ssh.h"
#include "storage.h"

#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

static struct ab_config cfg;
static volatile sig_atomic_t stopping;
static int logger_ready;
static int pf_ready;
static int ssh_ready;
static int storage_ready;
static char permanent_ips[STORAGE_MAX_ENTRIES][STORAGE_IP_LEN];
static size_t permanent_count;
static struct storage_temporary temporary_entries[STORAGE_MAX_ENTRIES];
static size_t temporary_count;

static void
on_signal(int sig)
{
    (void)sig;
    stopping = 1;
}

static int
restore_persistent_addresses(void)
{
    size_t i;
    time_t now = time(NULL);
    int expired = 0;

    if (now == (time_t)-1)
        return -1;
    if (storage_load_permanent(permanent_ips, STORAGE_MAX_ENTRIES,
                               &permanent_count) != 0 ||
        storage_load_temporary(temporary_entries, STORAGE_MAX_ENTRIES,
                               &temporary_count) != 0)
        return -1;

    for (i = 0; i < permanent_count; i++) {
        if (pf_ready && pf_perm_add(permanent_ips[i]) != 0)
            return -1;
    }

    for (i = 0; i < temporary_count; ) {
        if (temporary_entries[i].expires_at <= now) {
            if (pf_ready)
                (void)pf_temp_delete(temporary_entries[i].ip);
            memmove(&temporary_entries[i], &temporary_entries[i + 1],
                    (temporary_count - i - 1) * sizeof(temporary_entries[0]));
            temporary_count--;
            expired = 1;
            continue;
        }
        if (pf_ready && pf_temp_add(temporary_entries[i].ip) != 0)
            return -1;
        i++;
    }

    if (expired && storage_save_temporary(temporary_entries, temporary_count) != 0)
        return -1;
    logger_log("INFO", "Persistence restored: %zu permanent, %zu temporary IPs",
               permanent_count, temporary_count);
    return 0;
}

static void
expire_temporary_addresses(void)
{
    size_t i = 0;
    time_t now = time(NULL);
    int changed = 0;

    if (now == (time_t)-1)
        return;
    while (i < temporary_count) {
        if (temporary_entries[i].expires_at <= now) {
            if (pf_ready && pf_temp_delete(temporary_entries[i].ip) != 0)
                logger_log("ERROR", "Could not remove expired PF address %s",
                           temporary_entries[i].ip);
            memmove(&temporary_entries[i], &temporary_entries[i + 1],
                    (temporary_count - i - 1) * sizeof(temporary_entries[0]));
            temporary_count--;
            changed = 1;
        } else {
            i++;
        }
    }
    if (changed && storage_save_temporary(temporary_entries, temporary_count) != 0)
        logger_log("ERROR", "Could not persist expired temporary address cleanup");
}

int
core_init(const char *path)
{
    struct sigaction action;

    stopping = 0;
    logger_ready = 0;
    pf_ready = 0;
    ssh_ready = 0;
    storage_ready = 0;
    permanent_count = 0;
    temporary_count = 0;

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
    storage_ready = 1;

    if (cfg.enable_pf) {
        if (pf_init(cfg.pf_temp_table, cfg.pf_perm_table) != 0) {
            logger_log("ERROR", "Invalid or duplicate PF table names");
            core_shutdown();
            return -1;
        }
        pf_ready = 1;
    }

    if (restore_persistent_addresses() != 0) {
        logger_log("ERROR", "Cannot restore persistent IP lists");
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
        "AirBotz core initialized; automatic blocking is disabled");
    return 0;
}

int
core_run(void)
{
    while (!stopping) {
        ssh_process();
        expire_temporary_addresses();
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
    storage_ready = 0;
}
