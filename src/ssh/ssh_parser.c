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
        value = value * 10 + (unsigned long)(*p - '0');
        if (value > 65535)
            return 0;
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
    if (user_len >= 12 && memcmp(user, "invalid user ", 12) == 0) {
        event->invalid_user = 1;
        user += 12;
        user_len -= 12;
    }
    if (user_len) {
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

static void
classify_message(struct ssh_event *event, const char *message)
{
    const char *p;

    if (strncmp(message, "Failed password for ", 20) == 0) {
        event->type = SSH_EVENT_FAILED_PASSWORD;
        extract_user_and_address(event, message + 20, " from ");
    } else if (strncmp(message, "Failed none for ", 16) == 0) {
        event->type = SSH_EVENT_FAILED_NONE;
        extract_user_and_address(event, message + 16, " from ");
    } else if (strncmp(message, "Accepted password for ", 22) == 0) {
        event->type = SSH_EVENT_ACCEPTED_PASSWORD;
        extract_user_and_address(event, message + 22, " from ");
    } else if (strncmp(message, "Accepted publickey for ", 23) == 0) {
        event->type = SSH_EVENT_ACCEPTED_PUBLICKEY;
        extract_user_and_address(event, message + 23, " from ");
    } else if (strncmp(message, "Accepted keyboard-interactive for ", 34) == 0) {
        event->type = SSH_EVENT_ACCEPTED_KEYBOARD_INTERACTIVE;
        extract_user_and_address(event, message + 34, " from ");
    } else if (strncmp(message, "Invalid user ", 13) == 0) {
        event->type = SSH_EVENT_INVALID_USER;
        extract_user_and_address(event, message + 13, " from ");
    } else if (strstr(message, "authentication failure") != NULL) {
        event->type = SSH_EVENT_PAM_AUTH_FAILURE;
        p = strstr(message, "rhost=");
        if (p) {
            p += 6;
            if (is_ip_address(p, strcspn(p, " \t;"),
                              event->address, sizeof(event->address)))
                event->has_address = 1;
        }
    } else if (strncmp(message, "Received disconnect from ", 25) == 0) {
        event->type = SSH_EVENT_RECEIVED_DISCONNECT;
        p = message + 25;
        if (is_ip_address(p, strcspn(p, " \t:"),
                          event->address, sizeof(event->address)))
            event->has_address = 1;
    } else if (strncmp(message, "Disconnecting:", 14) == 0) {
        event->type = SSH_EVENT_SERVER_DISCONNECT;
    } else if (strncmp(message, "Connection closed", 17) == 0 ||
               strncmp(message, "Disconnected from", 18) == 0) {
        event->type = SSH_EVENT_CONNECTION_CLOSED;
        if (ssh_extract_address(message, event->address,
                                sizeof(event->address)))
            event->has_address = 1;
    } else if ((p = strstr(message, "session opened for user ")) != NULL) {
        const char *u = p + 24;
        const char *e = u;
        event->type = SSH_EVENT_SESSION_OPENED;
        while (*e && !isspace((unsigned char)*e))
            e++;
        copy_span(event->username, sizeof(event->username), u,
                  (size_t)(e - u));
        event->has_username = (e != u);
    } else if ((p = strstr(message, "session closed for user ")) != NULL) {
        const char *u = p + 24;
        const char *e = u;
        event->type = SSH_EVENT_SESSION_CLOSED;
        while (*e && !isspace((unsigned char)*e))
            e++;
        copy_span(event->username, sizeof(event->username), u,
                  (size_t)(e - u));
        event->has_username = (e != u);
    }
}

int
ssh_parse_record(const char *line, struct ssh_event *event)
{
    const char *cursor, *field, *month_start;
    size_t length;
    char process[64];
    char message[SSH_EVENT_MESSAGE_MAX];
    const char *colon;
    const char *message_start;
    const char *end;

    if (!line || !event)
        return -1;
    memset(event, 0, sizeof(*event));
    event->type = SSH_EVENT_UNKNOWN;

    cursor = line;
    if (!next_field(&cursor, &field, &length))
        return -1;
    month_start = field;
    if (length != 3)
        return -1;
    {
        char month[4];
        copy_span(month, sizeof(month), field, length);
        if (strstr("JanFebMarAprMayJunJulAugSepOctNovDec", month) == NULL)
            return -1;
    }
    {
        const char *day_start;
        size_t day_len;
        const char *time_start;
        size_t time_len;
        char timestamp[SSH_EVENT_TIME_MAX];
        if (!next_field(&cursor, &day_start, &day_len) ||
            !next_field(&cursor, &time_start, &time_len) ||
            !next_field(&cursor, &field, &length))
            return -1;
        if (day_len == 0 || day_len > 2 || time_len != 8 ||
            time_start[2] != ':' || time_start[5] != ':')
            return -1;
        if (snprintf(timestamp, sizeof(timestamp), "%.*s %.*s %.*s",
                     (int)3, month_start, (int)day_len, day_start,
                     (int)time_len, time_start) < 0)
            return -1;
        copy_span(event->timestamp, sizeof(event->timestamp),
                  timestamp, strlen(timestamp));
        event->has_timestamp = 1;
        copy_span(event->hostname, sizeof(event->hostname), field, length);
    }

    if (!next_field(&cursor, &field, &length))
        return -1;
    copy_span(process, sizeof(process), field, length);
    colon = strchr(process, ':');
    if (!colon)
        return -1;
    message_start = field + (colon - process) + 1;
    * (char *)colon = '\0';
    if (strncmp(process, "sshd[", 5) != 0 &&
        strncmp(process, "sshd-session[", 13) != 0)
        return -1;
    {
        const char *pid_start = strchr(process, '[');
        const char *pid_end = strrchr(process, ']');
        if (pid_start && pid_end && pid_end > pid_start + 1) {
            copy_span(event->pid, sizeof(event->pid), pid_start + 1,
                      (size_t)(pid_end - pid_start - 1));
            event->has_pid = 1;
        }
    }

    while (*message_start && isspace((unsigned char)*message_start))
        message_start++;
    end = message_start + strlen(message_start);
    while (end > message_start &&
           (end[-1] == '\r' || end[-1] == '\n'))
        end--;
    copy_span(message, sizeof(message), message_start,
              (size_t)(end - message_start));
    copy_span(event->message, sizeof(event->message), message,
              strlen(message));
    classify_message(event, message);
    return 0;
}
