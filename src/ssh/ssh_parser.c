#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>

int ssh_extract_address(const char *line, char *out, size_t cap) {
    const char *p, *end;
    char candidate[INET6_ADDRSTRLEN];
    unsigned char buf[sizeof(struct in6_addr)];

    if (!line || !out || cap < 2) return 0;
    p = strstr(line, " from ");
    if (!p) return 0;
    p += 6;
    end = p;
    while (*end && !isspace((unsigned char)*end) && *end != ',') end++;
    if ((size_t)(end - p) == 0 || (size_t)(end - p) >= sizeof(candidate)) return 0;
    memcpy(candidate, p, (size_t)(end - p));
    candidate[end - p] = '\0';

    if (inet_pton(AF_INET, candidate, buf) != 1 &&
        inet_pton(AF_INET6, candidate, buf) != 1) return 0;
    if (strlen(candidate) >= cap) return 0;
    strcpy(out, candidate);
    return 1;
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
