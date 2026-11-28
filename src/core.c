#include "core.h"
#include "address_manager.h"
#include "ipc.h"
#include "logger.h"
#include "pf.h"
#include "ssh.h"
#include "ssh_detection.h"
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
        const char *pf_state = "not-configured";
        char temp_state[24] = "unavailable";
        char perm_state[24] = "unavailable";

        if (manager->pf_enabled) {
            char entries[PF_SNAPSHOT_MAX_ENTRIES][PF_IP_LEN];
            size_t temp_count = 0, perm_count = 0;
            int enabled = 0;

            if (pf_get_status(&enabled) == 0)
                pf_state = enabled ? "enabled" : "disabled";
            else
                pf_state = "unavailable";

            if (pf_temp_snapshot(entries, PF_SNAPSHOT_MAX_ENTRIES,
                                 &temp_count) == 0)
                snprintf(temp_state, sizeof(temp_state), "%zu", temp_count);
            if (pf_perm_snapshot(entries, PF_SNAPSHOT_MAX_ENTRIES,
                                 &perm_count) == 0)
                snprintf(perm_state, sizeof(perm_state), "%zu", perm_count);
        }
        {
            struct ssh_reader_stats ss;
            struct ssh_detection_stats ds;
            ssh_get_stats(&ss);
            ssh_detection_get_stats(&ds);
            snprintf(response, response_size,
                "OK running permanent=%zu temporary=%zu pf=%s pf_temp_entries=%s pf_perm_entries=%s ssh_source=%s ssh_seen=%llu ssh_parsed=%llu ssh_classified=%llu ssh_unknown=%llu ssh_malformed=%llu ssh_oversized=%llu ssh_read_errors=%llu ssh_rotations=%llu ssh_missing=%llu ssh_recovered=%llu ssh_last_read=%lld ssh_last_record=%lld ssh_auth_failures=%llu ssh_bruteforce_findings=%llu ssh_password_spray_findings=%llu ssh_distributed_bruteforce_findings=%llu ssh_detection_active=%u ssh_detection_evictions=%llu ssh_detection_partial=%u\n",
                manager->permanent_count, manager->temporary_count,
                pf_state, temp_state, perm_state,
                ss.source_available ? "available" : "unavailable", ss.records_seen,
                ss.records_parsed, ss.events_classified, ss.events_unknown,
                ss.records_malformed, ss.records_oversized, ss.read_errors,
                ss.rotations, ss.missing_transitions, ss.recovery_transitions,
                (long long)ss.last_read_time, (long long)ss.last_record_time,
                ds.auth_failures_observed, ds.brute_force_findings,
                ds.password_spray_findings, ds.distributed_brute_force_findings,
                ds.active_observations, ds.capacity_evictions, ds.partial_visibility);
        }
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

static const char *
ssh_event_name(enum ssh_event_type type)
{
    switch (type) {
    case SSH_EVENT_FAILED_PASSWORD: return "failed_password";
    case SSH_EVENT_FAILED_NONE: return "failed_none";
    case SSH_EVENT_ACCEPTED_PASSWORD: return "accepted_password";
    case SSH_EVENT_ACCEPTED_PUBLICKEY: return "accepted_publickey";
    case SSH_EVENT_ACCEPTED_KEYBOARD_INTERACTIVE: return "accepted_keyboard_interactive";
    case SSH_EVENT_INVALID_USER: return "invalid_user";
    case SSH_EVENT_PAM_AUTH_FAILURE: return "pam_auth_failure";
    case SSH_EVENT_RECEIVED_DISCONNECT: return "received_disconnect";
    case SSH_EVENT_SERVER_DISCONNECT: return "server_disconnect";
    case SSH_EVENT_CONNECTION_CLOSED: return "connection_closed";
    case SSH_EVENT_SESSION_OPENED: return "session_opened";
    case SSH_EVENT_SESSION_CLOSED: return "session_closed";
    case SSH_EVENT_PAM_CHECK_PASS: return "pam_check_pass";
    case SSH_EVENT_PAM_FAILURE_SUMMARY: return "pam_failure_summary";
    case SSH_EVENT_PAM_MAX_RETRIES: return "pam_max_retries";
    case SSH_EVENT_REVERSE_DNS_WARNING: return "reverse_dns_warning";
    case SSH_EVENT_IDENTIFICATION_MISSING: return "identification_missing";
    case SSH_EVENT_SSHD_ERROR: return "sshd_error";
    case SSH_EVENT_SSHD_FATAL: return "sshd_fatal";
    case SSH_EVENT_TRANSPORT_ERROR: return "transport_error";
    case SSH_EVENT_BAD_PROTOCOL_VERSION: return "bad_protocol_version";
    case SSH_EVENT_BAD_PACKET_LENGTH: return "bad_packet_length";
    case SSH_EVENT_CORRUPTED_MAC: return "corrupted_mac";
    case SSH_EVENT_SERVER_LISTENING: return "server_listening";
    case SSH_EVENT_SYSLOGIN_LOGOUT_ERROR: return "syslogin_logout_error";
    case SSH_EVENT_UNKNOWN:
    default: return "unknown";
    }
}

static void
handle_ssh_event(const struct ssh_event *event, void *context)
{
    const char *severity = "unknown";
    const char *phase = "unknown";
    const char *operation = "unknown";
    const char *cause = "unknown";
    char port[16];

    (void)context;
    if (!event)
        return;
    ssh_detection_handle(event);
    if (event->type == SSH_EVENT_UNKNOWN)
        return;

    if (event->severity == SSH_LOG_SEVERITY_ERROR)
        severity = "error";
    else if (event->severity == SSH_LOG_SEVERITY_FATAL)
        severity = "fatal";
    if (event->auth_phase == SSH_AUTH_PHASE_PREAUTH)
        phase = "preauth";

    switch (event->transport_operation) {
    case SSH_TRANSPORT_OP_READ: operation = "read"; break;
    case SSH_TRANSPORT_OP_WRITE: operation = "write"; break;
    case SSH_TRANSPORT_OP_IDENTIFICATION: operation = "identification"; break;
    case SSH_TRANSPORT_OP_KEY_EXCHANGE: operation = "key_exchange"; break;
    case SSH_TRANSPORT_OP_NEGOTIATION: operation = "negotiation"; break;
    default: break;
    }
    switch (event->transport_cause) {
    case SSH_TRANSPORT_CAUSE_CONNECTION_RESET: cause = "connection_reset"; break;
    case SSH_TRANSPORT_CAUSE_TIMEOUT: cause = "timeout"; break;
    case SSH_TRANSPORT_CAUSE_BROKEN_PIPE: cause = "broken_pipe"; break;
    case SSH_TRANSPORT_CAUSE_EOF: cause = "eof"; break;
    default: break;
    }

    if (event->has_port)
        (void)snprintf(port, sizeof(port), "%u", event->port);
    else
        (void)snprintf(port, sizeof(port), "-");

    logger_log("SSH",
        "type=%s severity=%s phase=%s pid=%s user=%s address=%s port=%s operation=%s cause=%s packet_length=%u has_packet_length=%u repetition_summary=%u repetition_count=%u",
        ssh_event_name(event->type), severity, phase,
        event->has_pid ? event->pid : "-",
        event->has_username ? event->username : "-",
        event->has_address ? event->address : "-",
        port, operation, cause, event->packet_length, event->has_packet_length,
        event->is_repetition_summary, event->repetition_count);
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
    ssh_detection_reset();

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

    {
        int manager_rc = address_manager_init(&addresses, &pf_ops, pf_ready);
        if (manager_rc == 0)
            manager_rc = address_manager_restore(&addresses);
        if (manager_rc == -3) {
            logger_log("WARN", "Managed IP expiry cleanup committed; storage durability is uncertain");
        } else if (manager_rc != 0) {
            logger_log("ERROR", "Cannot initialize or restore managed IP addresses");
            core_shutdown();
            return -1;
        }
    }

    if (ssh_init(cfg.ssh_log, handle_ssh_event, NULL) != 0) {
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
        {
            int expire_rc = address_manager_expire(&addresses, time(NULL), &expired);
            if (expire_rc == -3)
                logger_log("ERROR", "Temporary IP expiry committed, but storage durability is uncertain");
            else if (expire_rc != 0)
                logger_log("ERROR", "Could not expire temporary PF addresses");
            else if (expired)
                logger_log("INFO", "Expired %zu temporary IP addresses", expired);
        }
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
