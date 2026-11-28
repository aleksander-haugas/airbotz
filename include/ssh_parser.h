#ifndef AIRBOTZ_SSH_PARSER_H
#define AIRBOTZ_SSH_PARSER_H

#include <stddef.h>

#define SSH_EVENT_MESSAGE_MAX 1024
#define SSH_EVENT_HOST_MAX 128
#define SSH_EVENT_USER_MAX 128
#define SSH_EVENT_PID_MAX 16
#define SSH_EVENT_TIME_MAX 32
#define SSH_EVENT_IP_MAX 46
#define SSH_EVENT_DISCONNECT_REASON_MAX 128

enum ssh_auth_phase {
    SSH_AUTH_PHASE_UNKNOWN = 0,
    SSH_AUTH_PHASE_PREAUTH
};

enum ssh_transport_operation {
    SSH_TRANSPORT_OP_UNKNOWN = 0,
    SSH_TRANSPORT_OP_READ,
    SSH_TRANSPORT_OP_WRITE,
    SSH_TRANSPORT_OP_IDENTIFICATION,
    SSH_TRANSPORT_OP_KEY_EXCHANGE,
    SSH_TRANSPORT_OP_NEGOTIATION
};

enum ssh_transport_cause {
    SSH_TRANSPORT_CAUSE_UNKNOWN = 0,
    SSH_TRANSPORT_CAUSE_CONNECTION_RESET,
    SSH_TRANSPORT_CAUSE_TIMEOUT,
    SSH_TRANSPORT_CAUSE_BROKEN_PIPE,
    SSH_TRANSPORT_CAUSE_EOF
};

enum ssh_event_type {
    SSH_EVENT_UNKNOWN = 0,
    SSH_EVENT_FAILED_PASSWORD,
    SSH_EVENT_FAILED_NONE,
    SSH_EVENT_ACCEPTED_PASSWORD,
    SSH_EVENT_ACCEPTED_PUBLICKEY,
    SSH_EVENT_ACCEPTED_KEYBOARD_INTERACTIVE,
    SSH_EVENT_INVALID_USER,
    SSH_EVENT_PAM_AUTH_FAILURE,
    SSH_EVENT_RECEIVED_DISCONNECT,
    SSH_EVENT_SERVER_DISCONNECT,
    SSH_EVENT_CONNECTION_CLOSED,
    SSH_EVENT_SESSION_OPENED,
    SSH_EVENT_SESSION_CLOSED,
    SSH_EVENT_PAM_CHECK_PASS,
    SSH_EVENT_PAM_FAILURE_SUMMARY,
    SSH_EVENT_PAM_MAX_RETRIES,
    SSH_EVENT_REVERSE_DNS_WARNING,
    SSH_EVENT_IDENTIFICATION_MISSING,
    SSH_EVENT_SSHD_ERROR,
    SSH_EVENT_SSHD_FATAL,
    SSH_EVENT_TRANSPORT_ERROR
};

enum ssh_log_severity {
    SSH_LOG_SEVERITY_UNKNOWN = 0,
    SSH_LOG_SEVERITY_ERROR,
    SSH_LOG_SEVERITY_FATAL
};

struct ssh_event {
    enum ssh_event_type type;
    enum ssh_log_severity severity;
    enum ssh_auth_phase auth_phase;
    enum ssh_transport_operation transport_operation;
    enum ssh_transport_cause transport_cause;
    char timestamp[SSH_EVENT_TIME_MAX];
    char hostname[SSH_EVENT_HOST_MAX];
    char pid[SSH_EVENT_PID_MAX];
    char username[SSH_EVENT_USER_MAX];
    char address[SSH_EVENT_IP_MAX];
    char message[SSH_EVENT_MESSAGE_MAX];
    char disconnect_reason[SSH_EVENT_DISCONNECT_REASON_MAX];
    unsigned int port;
    unsigned int disconnect_reason_code;
    unsigned int has_timestamp;
    unsigned int has_pid;
    unsigned int has_username;
    unsigned int has_address;
    unsigned int has_port;
    unsigned int invalid_user;
    unsigned int has_disconnect_reason_code;
    unsigned int has_disconnect_reason_text;
    /* Number of additional copies represented by a syslog repeat summary. */
    unsigned int repetition_count;
    unsigned int is_repetition_summary;
};

/*
 * Parse one syslog sshd record. Returns 0 for a valid sshd envelope,
 * including an unclassified message; returns -1 for invalid input/envelope.
 * The output is always bounded and contains no pointers into the input.
 */
int ssh_parse_record(const char *line, struct ssh_event *event);
/* Length-aware entry point: rejects embedded NUL bytes and oversized records. */
int ssh_parse_record_n(const void *data, size_t length, struct ssh_event *event);

#endif
