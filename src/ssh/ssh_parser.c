#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>

static int is_ip_address(const char *start, size_t length,
                         char *out, size_t cap) {
    char candidate[INET6_ADDRSTRLEN];
    unsigned char address[sizeof(struct in6_addr)];

    if (length == 0 || length >= sizeof(candidate) || length >= cap)
        return 0;

    memcpy(candidate, start, length);
    candidate[length] = '\0';

    if (inet_pton(AF_INET, candidate, address) != 1 &&
        inet_pton(AF_INET6, candidate, address) != 1)
        return 0;

    memcpy(out, candidate, length + 1);
    return 1;
}

int ssh_extract_address(const char *line, char *out, size_t cap) {
    const char *p;
    const char *markers[] = { " from ", " by " };
    size_t i;

    if (!line || !out || cap < 2)
        return 0;

    for (i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
        p = line;
        while ((p = strstr(p, markers[i])) != NULL) {
            const char *token;
            p += strlen(markers[i]);

            /*
             * OpenSSH messages vary: "from ::1", "by invalid user
             * name ::1", or "by authenticating user name ::1".
             * Scan the remaining fields and accept only a valid IP token.
             */
            token = p;
            while (*token) {
                const char *end;

                while (*token && isspace((unsigned char)*token))
                    token++;
                if (!*token)
                    break;

                end = token;
                while (*end && !isspace((unsigned char)*end) && *end != ',')
                    end++;

                if (is_ip_address(token, (size_t)(end - token), out, cap))
                    return 1;

                token = end;
                if (*token == ',')
                    token++;
            }
            p++;
        }
    }

    return 0;
}

const char *ssh_classify(const char *line) {
    if (!line) return "unknown";
    if (strstr(line, "Failed password") || strstr(line, "Invalid user") ||
        strstr(line, "authentication failure")) return "auth_failure";
    if (strstr(line, "Accepted password") || strstr(line, "Accepted publickey") ||
        strstr(line, "Accepted keyboard-interactive")) return "auth_success";
    if (strstr(line, "Connection closed") || strstr(line, "Disconnected from"))
        return "connection_closed";
    return "other";
}

#include "ssh_parser.h"
#include <stdio.h>
#include <stdlib.h>

static void
copy_span(char *dst, size_t cap, const char *src, size_t len)
{
    if (cap == 0)
        return;
    if (len >= cap)
        len = cap - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static int
next_field(const char **cursor, const char **start, size_t *length)
{
    const char *p = *cursor;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (!*p)
        return 0;
    *start = p;
    while (*p && !isspace((unsigned char)*p))
        p++;
    *length = (size_t)(p - *start);
    *cursor = p;
    return 1;
}

static int
parse_port(const char *p, unsigned int *port)
{
    unsigned long value = 0;
    if (!p || !*p)
        return 0;
    while (*p) {
        if (!isdigit((unsigned char)*p))
            return 0;
        {
            unsigned long digit = (unsigned long)(*p - '0');
            if (value > (65535UL - digit) / 10UL)
                return 0;
            value = value * 10UL + digit;
        }
        p++;
    }
    if (value == 0)
        return 0;
    *port = (unsigned int)value;
    return 1;
}

static void
extract_user_and_address(struct ssh_event *event, const char *text,
                         const char *separator)
{
    const char *split = strstr(text, separator);
    const char *user = text;
    const char *end;
    const char *ip;
    size_t user_len;

    if (!split)
        return;
    user_len = (size_t)(split - user);
    while (user_len && isspace((unsigned char)user[user_len - 1]))
        user_len--;
    if (user_len >= 13 && memcmp(user, "invalid user ", 13) == 0) {
        event->invalid_user = 1;
        user += 13;
        user_len -= 13;
    }
    if (user_len && user_len < sizeof(event->username)) {
        copy_span(event->username, sizeof(event->username), user, user_len);
        event->has_username = 1;
    }

    ip = split + strlen(separator);
    while (*ip && isspace((unsigned char)*ip))
        ip++;
    end = ip;
    while (*end && !isspace((unsigned char)*end) && *end != ',')
        end++;
    if (is_ip_address(ip, (size_t)(end - ip),
                      event->address, sizeof(event->address)))
        event->has_address = 1;

    if (strncmp(end, " port ", 6) == 0) {
        const char *port_start = end + 6;
        char portbuf[8];
        const char *port_end = port_start;
        while (*port_end && isdigit((unsigned char)*port_end))
            port_end++;
        copy_span(portbuf, sizeof(portbuf), port_start,
                  (size_t)(port_end - port_start));
        if (parse_port(portbuf, &event->port))
            event->has_port = 1;
    }
}

static int
classify_transport(struct ssh_event *event, const char *body)
{
    /* Preserve protocol direction/lifecycle events even if peer text mentions
     * a transport-like phrase such as "Connection reset". */
    if (strncmp(body, "Received disconnect from ", 25) == 0 ||
        strncmp(body, "Disconnecting:", 14) == 0 ||
        strncmp(body, "Connection closed", 17) == 0 ||
        strncmp(body, "Disconnected from", 18) == 0)
        return 0;

    if (strncmp(body, "Read from socket failed:", 24) == 0) {
        event->transport_operation = SSH_TRANSPORT_OP_READ;
    } else if (strncmp(body, "Write failed:", 13) == 0) {
        event->transport_operation = SSH_TRANSPORT_OP_WRITE;
    } else if (strncmp(body, "banner exchange:", 16) == 0) {
        event->transport_operation = SSH_TRANSPORT_OP_IDENTIFICATION;
    } else if (strncmp(body, "kex_exchange_identification",
                       sizeof("kex_exchange_identification") - 1) == 0) {
        event->transport_operation = SSH_TRANSPORT_OP_KEY_EXCHANGE;
    } else if (strncmp(body, "Unable to negotiate",
                       sizeof("Unable to negotiate") - 1) == 0 ||
               strncmp(body, "no matching ",
                       sizeof("no matching ") - 1) == 0) {
        event->transport_operation = SSH_TRANSPORT_OP_NEGOTIATION;
    }

    /*
     * Only interpret a cause when the message is anchored by a recognized
     * transport operation, or when the cause itself is the whole message
     * prefix. Incidental words in unrelated diagnostics must not promote
     * them into transport events.
     */
    if (event->transport_operation == SSH_TRANSPORT_OP_UNKNOWN &&
        strncmp(body, "Connection reset",
                sizeof("Connection reset") - 1) != 0 &&
        strncmp(body, "Connection timed out",
                sizeof("Connection timed out") - 1) != 0 &&
        strncmp(body, "Operation timed out",
                sizeof("Operation timed out") - 1) != 0 &&
        strncmp(body, "Broken pipe", sizeof("Broken pipe") - 1) != 0 &&
        strncmp(body, "End of file", sizeof("End of file") - 1) != 0 &&
        strncmp(body, "unexpected EOF", sizeof("unexpected EOF") - 1) != 0)
        return 0;

    if (strstr(body, "Connection reset by peer") != NULL ||
        strncmp(body, "Connection reset", sizeof("Connection reset") - 1) == 0) {
        event->transport_cause = SSH_TRANSPORT_CAUSE_CONNECTION_RESET;
    } else if (strstr(body, "Connection timed out") != NULL ||
               strstr(body, "Operation timed out") != NULL) {
        event->transport_cause = SSH_TRANSPORT_CAUSE_TIMEOUT;
    } else if (strstr(body, "Broken pipe") != NULL) {
        event->transport_cause = SSH_TRANSPORT_CAUSE_BROKEN_PIPE;
    } else if (strstr(body, "End of file") != NULL ||
               strstr(body, "unexpected EOF") != NULL) {
        event->transport_cause = SSH_TRANSPORT_CAUSE_EOF;
    }

    if (event->transport_operation != SSH_TRANSPORT_OP_UNKNOWN ||
        event->transport_cause != SSH_TRANSPORT_CAUSE_UNKNOWN) {
        event->type = SSH_EVENT_TRANSPORT_ERROR;
        return 1;
    }
    return 0;
}

/*
 * Decode syslogd's compressed duplicate form:
 * "message repeated N times: [ <original message>]".
 * N is the number of additional copies, not a new independent attempt.
 */
static int
unwrap_repetition_summary(const char *message, char *original,
                          size_t original_cap, unsigned int *count)
{
    static const char prefix[] = "message repeated ";
    static const char middle[] = " times: [";
    const char *p, *body, *end;
    unsigned int value = 0;
    size_t body_len;

    if (!message || !original || !count ||
        strncmp(message, prefix, sizeof(prefix) - 1) != 0)
        return 0;

    p = message + sizeof(prefix) - 1;
    if (!isdigit((unsigned char)*p))
        return 0;

    while (isdigit((unsigned char)*p)) {
        unsigned int digit = (unsigned int)(*p - '0');
        if (value > (~0U - digit) / 10U)
            return 0;
        value = value * 10U + digit;
        p++;
    }
    if (value == 0 || strncmp(p, middle, sizeof(middle) - 1) != 0)
        return 0;

    body = p + sizeof(middle) - 1;
    end = message + strlen(message);
    if (end <= body || end[-1] != ']')
        return 0;
    end--;

    while (body < end && isspace((unsigned char)*body))
        body++;
    while (end > body && isspace((unsigned char)end[-1]))
        end--;
    body_len = (size_t)(end - body);
    if (body_len == 0 || body_len >= original_cap)
        return 0;

    copy_span(original, original_cap, body, body_len);
    *count = value;
    return 1;
}

static void
classify_message(struct ssh_event *event, const char *message)
{
    const char *p;
    const char *body = message;

    if (strstr(message, "[preauth]") != NULL)
        event->auth_phase = SSH_AUTH_PHASE_PREAUTH;

    if (strncmp(body, "error:", 6) == 0 &&
        isspace((unsigned char)body[6])) {
        event->severity = SSH_LOG_SEVERITY_ERROR;
        body += 6;
        while (*body && isspace((unsigned char)*body))
            body++;
    } else if (strncmp(body, "fatal:", 6) == 0 &&
               isspace((unsigned char)body[6])) {
        event->severity = SSH_LOG_SEVERITY_FATAL;
        body += 6;
        while (*body && isspace((unsigned char)*body))
            body++;
    }

    if (classify_transport(event, body))
        return;

    if (strncmp(body, "Failed password for ", 20) == 0) {
        event->type = SSH_EVENT_FAILED_PASSWORD;
        extract_user_and_address(event, body + 20, " from ");
    } else if (strncmp(body, "Failed none for ", 16) == 0) {
        event->type = SSH_EVENT_FAILED_NONE;
        extract_user_and_address(event, body + 16, " from ");
    } else if (strncmp(body, "Accepted password for ", 22) == 0) {
        event->type = SSH_EVENT_ACCEPTED_PASSWORD;
        extract_user_and_address(event, body + 22, " from ");
    } else if (strncmp(body, "Accepted publickey for ", 23) == 0) {
        event->type = SSH_EVENT_ACCEPTED_PUBLICKEY;
        extract_user_and_address(event, body + 23, " from ");
    } else if (strncmp(body, "Accepted keyboard-interactive for ", 34) == 0) {
        event->type = SSH_EVENT_ACCEPTED_KEYBOARD_INTERACTIVE;
        extract_user_and_address(event, body + 34, " from ");
    } else if (strncmp(body, "Invalid user ", 13) == 0) {
        event->type = SSH_EVENT_INVALID_USER;
        extract_user_and_address(event, body + 13, " from ");
    } else if (strncmp(body, "input_userauth_request: invalid user ", 37) == 0) {
        const char *username = body + 37;
        const char *username_end = username;
        event->type = SSH_EVENT_INVALID_USER;
        event->invalid_user = 1;
        while (*username_end && !isspace((unsigned char)*username_end))
            username_end++;
        if (username_end > username &&
            (size_t)(username_end - username) < sizeof(event->username)) {
            copy_span(event->username, sizeof(event->username), username,
                      (size_t)(username_end - username));
            event->has_username = 1;
        }
    } else if (strncmp(body, "Disconnecting:", 14) == 0) {
        event->type = SSH_EVENT_SERVER_DISCONNECT;
    } else if (strncmp(body, "Received disconnect from ", 25) == 0) {
        const char *address_end;
        const char *cursor;
        const char *port_start;
        const char *port_end;
        const char *code_start;
        const char *code_end;
        const char *reason_start;
        const char *reason_end;
        char port_buffer[8];
        unsigned int reason_code = 0;

        event->type = SSH_EVENT_RECEIVED_DISCONNECT;
        p = body + 25;
        address_end = p;
        while (*address_end &&
               !isspace((unsigned char)*address_end) &&
               !(address_end[0] == ':' && address_end[1] == ' '))
            address_end++;
        if (is_ip_address(p, (size_t)(address_end - p),
                          event->address, sizeof(event->address)))
            event->has_address = 1;

        cursor = address_end;
        while (*cursor && isspace((unsigned char)*cursor))
            cursor++;
        if (strncmp(cursor, "port ", 5) == 0) {
            port_start = cursor + 5;
            port_end = port_start;
            while (*port_end && isdigit((unsigned char)*port_end))
                port_end++;
            if (port_end > port_start &&
                (size_t)(port_end - port_start) < sizeof(port_buffer)) {
                copy_span(port_buffer, sizeof(port_buffer), port_start,
                          (size_t)(port_end - port_start));
                if (parse_port(port_buffer, &event->port))
                    event->has_port = 1;
            }
            cursor = port_end;
            while (*cursor && isspace((unsigned char)*cursor))
                cursor++;
        }

        if (cursor[0] == ':' && cursor[1] == ' ') {
            code_start = cursor + 2;
            code_end = code_start;
            while (*code_end && isdigit((unsigned char)*code_end))
                code_end++;
            if (code_end > code_start && code_end[0] == ':' &&
                code_end[1] == ' ') {
                const char *digit;
                int valid_code = 1;
                for (digit = code_start; digit < code_end; digit++) {
                    unsigned int value = (unsigned int)(*digit - '0');
                    if (reason_code > (255U - value) / 10U) {
                        valid_code = 0;
                        break;
                    }
                    reason_code = reason_code * 10U + value;
                }
                if (valid_code) {
                    event->disconnect_reason_code = reason_code;
                    event->has_disconnect_reason_code = 1;
                    reason_start = code_end + 2;
                    reason_end = strstr(reason_start, " [preauth]");
                    if (!reason_end)
                        reason_end = reason_start + strlen(reason_start);
                    while (reason_end > reason_start &&
                           isspace((unsigned char)reason_end[-1]))
                        reason_end--;
                    if (reason_end > reason_start &&
                        (size_t)(reason_end - reason_start) <
                            sizeof(event->disconnect_reason)) {
                        copy_span(event->disconnect_reason,
                                  sizeof(event->disconnect_reason),
                                  reason_start,
                                  (size_t)(reason_end - reason_start));
                        event->has_disconnect_reason_text = 1;
                    }
                }
            }
        }
    } else if (strstr(body, "pam_unix(sshd:auth): check pass;") != NULL) {
        event->type = SSH_EVENT_PAM_CHECK_PASS;
    } else if (strncmp(body, "PAM ", 4) == 0 &&
               strstr(body, " more authentication failures;") != NULL) {
        event->type = SSH_EVENT_PAM_FAILURE_SUMMARY;
    } else if (strncmp(body, "PAM service(sshd) ignoring max retries;", 39) == 0) {
        event->type = SSH_EVENT_PAM_MAX_RETRIES;
    } else if (strstr(body, "authentication failure") != NULL) {
        event->type = SSH_EVENT_PAM_AUTH_FAILURE;
        p = strstr(body, "rhost=");
        if (p) {
            p += 6;
            if (is_ip_address(p, strcspn(p, " \\t;"),
                              event->address, sizeof(event->address)))
                event->has_address = 1;
        }
    } else if (strncmp(body, "reverse mapping checking getaddrinfo for ", 41) == 0) {
        const char *open_bracket = strchr(body, '[');
        const char *close_bracket = open_bracket ? strchr(open_bracket + 1, ']') : NULL;
        event->type = SSH_EVENT_REVERSE_DNS_WARNING;
        if (open_bracket && close_bracket &&
            is_ip_address(open_bracket + 1,
                          (size_t)(close_bracket - open_bracket - 1),
                          event->address, sizeof(event->address)))
            event->has_address = 1;
    } else if (strncmp(body, "Address ", 8) == 0) {
        static const char suffix[] =
            "but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!";
        const char *address = body + 8;
        const char *address_end = address;
        while (*address_end && !isspace((unsigned char)*address_end))
            address_end++;
        if (strncmp(address_end, " maps to ", 9) == 0) {
            const char *mapping = address_end + 9;
            const char *suffix_pos = strstr(mapping, ", ");
            if (suffix_pos && strcmp(suffix_pos + 2, suffix) == 0) {
                event->type = SSH_EVENT_REVERSE_DNS_WARNING;
                if (is_ip_address(address, (size_t)(address_end - address),
                                  event->address, sizeof(event->address)))
                    event->has_address = 1;
            }
        }
    } else if (strncmp(body, "Did not receive identification string from ", 43) == 0) {
        const char *address_start = body + 43;
        const char *address_end = address_start;
        event->type = SSH_EVENT_IDENTIFICATION_MISSING;
        while (*address_end && !isspace((unsigned char)*address_end))
            address_end++;
        if (is_ip_address(address_start,
                          (size_t)(address_end - address_start),
                          event->address, sizeof(event->address)))
            event->has_address = 1;
    } else if (strncmp(body, "Connection closed", 17) == 0 ||
               strncmp(body, "Disconnected from", 18) == 0) {
        event->type = SSH_EVENT_CONNECTION_CLOSED;
        if (ssh_extract_address(body, event->address,
                                sizeof(event->address)))
            event->has_address = 1;
    } else if ((p = strstr(body, "session opened for user ")) != NULL) {
        const char *u = p + 24;
        const char *e = u;
        event->type = SSH_EVENT_SESSION_OPENED;
        while (*e && !isspace((unsigned char)*e))
            e++;
        if (e > u && (size_t)(e - u) < sizeof(event->username)) {
            copy_span(event->username, sizeof(event->username), u,
                      (size_t)(e - u));
            event->has_username = 1;
        }
    } else if ((p = strstr(body, "session closed for user ")) != NULL) {
        const char *u = p + 24;
        const char *e = u;
        event->type = SSH_EVENT_SESSION_CLOSED;
        while (*e && !isspace((unsigned char)*e))
            e++;
        if (e > u && (size_t)(e - u) < sizeof(event->username)) {
            copy_span(event->username, sizeof(event->username), u,
                      (size_t)(e - u));
            event->has_username = 1;
        }
    } else if (event->severity == SSH_LOG_SEVERITY_FATAL) {
        event->type = SSH_EVENT_SSHD_FATAL;
    } else if (event->severity == SSH_LOG_SEVERITY_ERROR) {
        event->type = SSH_EVENT_SSHD_ERROR;
    }
}

static int
parse_decimal_range(const char *text, size_t length,
                    unsigned int minimum, unsigned int maximum,
                    unsigned int *value)
{
    size_t i;
    unsigned int result = 0;

    if (!text || length == 0 || !value)
        return 0;
    for (i = 0; i < length; i++) {
        unsigned int digit;
        if (!isdigit((unsigned char)text[i]))
            return 0;
        digit = (unsigned int)(text[i] - '0');
        if (digit > maximum || result > (maximum - digit) / 10U)
            return 0;
        result = result * 10U + digit;
    }
    if (result < minimum || result > maximum)
        return 0;
    *value = result;
    return 1;
}

static int
valid_month(const char *month)
{
    static const char *const months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    size_t i;

    for (i = 0; i < sizeof(months) / sizeof(months[0]); i++) {
        if (memcmp(month, months[i], 3) == 0)
            return 1;
    }
    return 0;
}

static unsigned int
month_max_day(const char *month)
{
    if (memcmp(month, "Feb", 3) == 0)
        return 29U;
    if (memcmp(month, "Apr", 3) == 0 ||
        memcmp(month, "Jun", 3) == 0 ||
        memcmp(month, "Sep", 3) == 0 ||
        memcmp(month, "Nov", 3) == 0)
        return 30U;
    return 31U;
}

static int
valid_process_field(const char *field, size_t length,
                    char *pid_out, size_t pid_cap)
{
    size_t prefix_len;
    size_t pid_len;
    unsigned int pid_value;

    if (length > 5 && memcmp(field, "sshd[", 5) == 0) {
        prefix_len = 5;
    } else if (length > 13 &&
               memcmp(field, "sshd-session[", 13) == 0) {
        prefix_len = 13;
    } else {
        return 0;
    }

    if (field[length - 1] != ':')
        return 0;
    if (length < prefix_len + 3 ||
        field[length - 2] != ']')
        return 0;

    pid_len = length - prefix_len - 2;
    if (pid_len == 0 || pid_len >= pid_cap ||
        !parse_decimal_range(field + prefix_len, pid_len,
                             1U, 2147483647U, &pid_value))
        return 0;

    copy_span(pid_out, pid_cap, field + prefix_len, pid_len);
    return 1;
}

static int
ssh_parse_record_cstr(const char *line, struct ssh_event *event)
{
    const char *cursor, *field, *month_start;
    const char *day_start, *time_start, *hostname_start;
    const char *process_start, *message_start, *end, *record_end, *scan;
    size_t length, day_len, time_len, hostname_len, process_len;
    size_t message_len;
    unsigned int day, hour, minute, second;
    char timestamp[SSH_EVENT_TIME_MAX];
    char message[SSH_EVENT_MESSAGE_MAX];
    char normalized_message[SSH_EVENT_MESSAGE_MAX];
    unsigned int repetition_count = 0;

    if (!line || !event)
        return -1;
    memset(event, 0, sizeof(*event));
    event->type = SSH_EVENT_UNKNOWN;

    /*
     * Permit one optional LF, CRLF, or CR record terminator, but reject
     * embedded line breaks anywhere in the syslog envelope or message.
     * Otherwise next_field() could silently parse across record boundaries.
     */
    record_end = line + strlen(line);
    if (record_end > line && record_end[-1] == '\n') {
        record_end--;
        if (record_end > line && record_end[-1] == '\r')
            record_end--;
    } else if (record_end > line && record_end[-1] == '\r') {
        record_end--;
    }
    for (scan = line; scan < record_end; scan++) {
        if (*scan == '\r' || *scan == '\n')
            return -1;
    }

    cursor = line;
    if (!next_field(&cursor, &field, &length) || length != 3 ||
        !valid_month(field))
        return -1;
    month_start = field;

    if (!next_field(&cursor, &day_start, &day_len) ||
        !next_field(&cursor, &time_start, &time_len) ||
        !next_field(&cursor, &hostname_start, &hostname_len))
        return -1;

    if (day_len > 2 ||
        !parse_decimal_range(day_start, day_len, 1U,
                             month_max_day(month_start), &day) ||
        time_len != 8 || time_start[2] != ':' || time_start[5] != ':' ||
        !parse_decimal_range(time_start, 2, 0U, 23U, &hour) ||
        !parse_decimal_range(time_start + 3, 2, 0U, 59U, &minute) ||
        !parse_decimal_range(time_start + 6, 2, 0U, 59U, &second))
        return -1;

    if (hostname_len == 0 || hostname_len >= sizeof(event->hostname))
        return -1;

    if (snprintf(timestamp, sizeof(timestamp), "%.*s %.*s %.*s",
                 3, month_start, (int)day_len, day_start,
                 (int)time_len, time_start) < 0)
        return -1;
    copy_span(event->timestamp, sizeof(event->timestamp),
              timestamp, strlen(timestamp));
    event->has_timestamp = 1;
    copy_span(event->hostname, sizeof(event->hostname),
              hostname_start, hostname_len);

    if (!next_field(&cursor, &process_start, &process_len) ||
        !valid_process_field(process_start, process_len,
                             event->pid, sizeof(event->pid)))
        return -1;
    event->has_pid = 1;

    message_start = cursor;
    while (*message_start && isspace((unsigned char)*message_start))
        message_start++;
    end = message_start + strlen(message_start);
    while (end > message_start &&
           (end[-1] == '\r' || end[-1] == '\n'))
        end--;
    message_len = (size_t)(end - message_start);

    if (message_len == 0 || message_len >= sizeof(message))
        return -1;
    {
        const char *scan;
        for (scan = message_start; scan < end; scan++) {
            if (*scan == '\r' || *scan == '\n')
                return -1;
        }
    }

    copy_span(message, sizeof(message), message_start, message_len);
    if (unwrap_repetition_summary(message, normalized_message,
                                  sizeof(normalized_message),
                                  &repetition_count)) {
        event->is_repetition_summary = 1;
        event->repetition_count = repetition_count;
        copy_span(event->message, sizeof(event->message),
                  normalized_message, strlen(normalized_message));
        classify_message(event, normalized_message);
    } else {
        copy_span(event->message, sizeof(event->message), message, message_len);
        classify_message(event, message);
    }
    return 0;
}


#define SSH_PARSE_RECORD_MAX 4096U

int
ssh_parse_record_n(const void *data, size_t length, struct ssh_event *event)
{
    char *record;
    int result;

    if (!event)
        return -1;
    memset(event, 0, sizeof(*event));
    event->type = SSH_EVENT_UNKNOWN;

    if (!data || length == 0 || length > SSH_PARSE_RECORD_MAX ||
        memchr(data, '\0', length) != NULL)
        return -1;

    record = malloc(length + 1);
    if (!record)
        return -1;
    memcpy(record, data, length);
    record[length] = '\0';

    result = ssh_parse_record_cstr(record, event);
    free(record);
    return result;
}

int
ssh_parse_record(const char *line, struct ssh_event *event)
{
    if (!line || !event)
        return -1;
    return ssh_parse_record_cstr(line, event);
}
