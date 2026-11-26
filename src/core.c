#include "core.h"
#include "address_manager.h"
#include "ipc.h"
#include "logger.h"
#include "pf.h"
#include "ssh.h"
#include "storage.h"

#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static struct ab_config cfg;
static struct address_manager addresses;
static volatile sig_atomic_t stopping;
static int logger_ready;
static int pf_ready;
static int ssh_ready;
static int ipc_ready;

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

static int
append_text(char *out, size_t size, size_t *used, const char *fmt,
            const char *ip, const char *when)
{
    int n;
    if (*used >= size) return -1;
    n = snprintf(out + *used, size - *used, fmt, ip, when);
    if (n < 0 || (size_t)n >= size - *used) return -1;
    *used += (size_t)n;
    return 0;
}

static int
handle_ipc_request(const char *request, char *response, size_t response_size,
                   void *context)
{
    char copy[256], *tokens[4], *save = NULL, *token;
    size_t count = 0, used = 0, i;
    struct address_manager *manager = context;

    if (!request || strlen(request) >= sizeof(copy)) {
        snprintf(response, response_size, "ERROR invalid request\n");
        return -1;
    }
    snprintf(copy, sizeof(copy), "%s", request);
    for (token = strtok_r(copy, " ", &save); token;
         token = strtok_r(NULL, " ", &save)) {
        if (count == 4) {
            snprintf(response, response_size, "ERROR too many arguments\n");
            return -1;
        }
        tokens[count++] = token;
    }
    if (count == 1 && strcmp(tokens[0], "STATUS") == 0) {
        snprintf(response, response_size,
            "OK running permanent=%zu temporary=%zu pf=%s\n",
            manager->permanent_count, manager->temporary_count,
            manager->pf_enabled ? "enabled" : "disabled");
        return 0;
    }
    if (count == 1 && strcmp(tokens[0], "LIST") == 0) {
        if (append_text(response, response_size, &used, "OK\n", "", "") != 0)
            return -1;
        for (i = 0; i < manager->permanent_count; i++) {
            if (append_text(response, response_size, &used,
                            "permanent %s\n", manager->permanent[i], "") != 0) {
                snprintf(response, response_size,
                         "ERROR IP list exceeds response capacity\n");
                return -1;
            }
        }
        for (i = 0; i < manager->temporary_count; i++) {
            struct tm tmv;
            char expiry[32];
            if (!gmtime_r(&manager->temporary[i].expires_at, &tmv) ||
                strftime(expiry, sizeof(expiry), "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0)
                snprintf(expiry, sizeof(expiry), "unknown");
            if (append_text(response, response_size, &used,
                            "temporary %s expires=%s\n",
                            manager->temporary[i].ip, expiry) != 0) {
                snprintf(response, response_size,
                         "ERROR IP list exceeds response capacity\n");
                return -1;
            }
        }
        return 0;
    }
    if (count == 3 && strcmp(tokens[0], "ADD_PERM") == 0 &&
        pf_valid_address(tokens[1]) && strcmp(tokens[2], "permanent") == 0) {
        int rc = address_manager_add_permanent(manager, tokens[1]);
        snprintf(response, response_size, rc == 0 ? "OK permanent address added\n" :
                 rc == -3 ? "ERROR state changed; storage durability uncertain\n" :
                 rc == -2 ? "ERROR PF rollback failed; inspect PF and storage\n" :
                            "ERROR could not add permanent address\n");
        return rc;
    }
    if (count == 3 && strcmp(tokens[0], "DEL_PERM") == 0 &&
        pf_valid_address(tokens[1]) && strcmp(tokens[2], "permanent") == 0) {
        int rc = address_manager_delete_permanent(manager, tokens[1]);
        snprintf(response, response_size, rc == 0 ? "OK permanent address removed\n" :
                 rc == -3 ? "ERROR state changed; storage durability uncertain\n" :
                 rc == -2 ? "ERROR PF rollback failed; inspect PF and storage\n" :
                            "ERROR could not remove permanent address\n");
        return rc;
    }
    if (count == 4 && strcmp(tokens[0], "ADD_TEMP") == 0 &&
        pf_valid_address(tokens[1]) && strcmp(tokens[2], "temporary") == 0) {
        char *end;
        unsigned long seconds;
        time_t now = time(NULL), expiry;
        errno = 0;
        seconds = strtoul(tokens[3], &end, 10);
        if (errno || !*tokens[3] || *end || seconds < 1 ||
            seconds > 31536000UL) {
            snprintf(response, response_size, "ERROR duration must be 1..31536000 seconds\n");
            return -1;
        }
        expiry = now + (time_t)seconds;
        if (expiry < now) {
            snprintf(response, response_size, "ERROR invalid expiration time\n");
            return -1;
        }
        {
            int rc = address_manager_add_temporary(manager, tokens[1], expiry);
            snprintf(response, response_size, rc == 0 ? "OK temporary address added\n" :
                     rc == -3 ? "ERROR state changed; storage durability uncertain\n" :
                 rc == -2 ? "ERROR PF rollback failed; inspect PF and storage\n" :
                                "ERROR could not add temporary address\n");
            return rc;
        }
    }
    if (count == 3 && strcmp(tokens[0], "DEL_TEMP") == 0 &&
        pf_valid_address(tokens[1]) && strcmp(tokens[2], "temporary") == 0) {
        int rc = address_manager_delete_temporary(manager, tokens[1]);
        snprintf(response, response_size, rc == 0 ? "OK temporary address removed\n" :
                 rc == -3 ? "ERROR state changed; storage durability uncertain\n" :
                 rc == -2 ? "ERROR PF rollback failed; inspect PF and storage\n" :
                            "ERROR could not remove temporary address\n");
        return rc;
    }
    snprintf(response, response_size, "ERROR invalid command or arguments\n");
    return -1;
}

int
core_init(const char *path)
{
    struct sigaction action;

    stopping = 0;
    logger_ready = 0;
    pf_ready = 0;
    ssh_ready = 0;
    ipc_ready = 0;

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

    if (ipc_init(cfg.socket_path, handle_ipc_request, &addresses) != 0) {
        logger_log("ERROR", "Cannot create root-only control socket %s",
                   cfg.socket_path);
        core_shutdown();
        return -1;
    }
    ipc_ready = 1;

    logger_log("INFO",
        "Persistence restored: %zu permanent, %zu temporary IPs",
        addresses.permanent_count, addresses.temporary_count);
    logger_log("INFO",
        "Control socket ready at %s; automatic blocking is disabled",
        cfg.socket_path);
    return 0;
}

int
core_run(void)
{
    while (!stopping) {
        size_t expired = 0;
        ssh_process();
        if (ipc_process() != 0)
            logger_log("ERROR", "Control socket processing failed");
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
    if (ipc_ready) {
        ipc_shutdown();
        ipc_ready = 0;
    }
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
