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
