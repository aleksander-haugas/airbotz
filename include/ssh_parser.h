#ifndef AIRBOTZ_SSH_PARSER_H
#define AIRBOTZ_SSH_PARSER_H

#include <stddef.h>

#define SSH_EVENT_MESSAGE_MAX 1024
#define SSH_EVENT_HOST_MAX 128
#define SSH_EVENT_USER_MAX 128
#define SSH_EVENT_PID_MAX 16
#define SSH_EVENT_TIME_MAX 32
#define SSH_EVENT_IP_MAX 46

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
    SSH_EVENT_SSHD_FATAL
};

enum ssh_log_severity {
    SSH_LOG_SEVERITY_UNKNOWN = 0,
    SSH_LOG_SEVERITY_ERROR,
    SSH_LOG_SEVERITY_FATAL
};

struct ssh_event {
    enum ssh_event_type type;
    enum ssh_log_severity severity;
    char timestamp[SSH_EVENT_TIME_MAX];
    char hostname[SSH_EVENT_HOST_MAX];
    char pid[SSH_EVENT_PID_MAX];
    char username[SSH_EVENT_USER_MAX];
    char address[SSH_EVENT_IP_MAX];
    char message[SSH_EVENT_MESSAGE_MAX];
    unsigned int port;
    unsigned int has_timestamp;
    unsigned int has_pid;
    unsigned int has_username;
    unsigned int has_address;
    unsigned int has_port;
    unsigned int invalid_user;
};

/*
 * Parse one syslog sshd record. Returns 0 for a valid sshd envelope,
 * including an unclassified message; returns -1 for invalid input/envelope.
 * The output is always bounded and contains no pointers into the input.
 */
int ssh_parse_record(const char *line, struct ssh_event *event);

#endif
