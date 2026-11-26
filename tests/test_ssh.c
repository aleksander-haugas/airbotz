#include <assert.h>
#include <string.h>
#include <stddef.h>

int ssh_extract_address(const char *, char *, size_t);
const char *ssh_classify(const char *);

int main(void) {
    char ip[64];

    assert(ssh_extract_address(
        "sshd: Failed password for root from 192.0.2.1 port 22 ssh2",
        ip, sizeof(ip)));
    assert(strcmp(ip, "192.0.2.1") == 0);

    assert(ssh_extract_address(
        "sshd: Failed password for root from 2001:db8::1 port 22 ssh2",
        ip, sizeof(ip)));
    assert(strcmp(ip, "2001:db8::1") == 0);

    assert(ssh_extract_address(
        "sshd-session: Connection closed by invalid user test ::1 port 46960 [preauth]",
        ip, sizeof(ip)));
    assert(strcmp(ip, "::1") == 0);

    assert(ssh_extract_address(
        "sshd-session: Connection closed by authenticating user test 192.0.2.8 port 22",
        ip, sizeof(ip)));
    assert(strcmp(ip, "192.0.2.8") == 0);

    assert(!ssh_extract_address(
        "sshd: Failed password for root from not-an-ip port 22",
        ip, sizeof(ip)));

    assert(strcmp(ssh_classify("Failed password"), "auth_failure") == 0);
    assert(strcmp(ssh_classify("Accepted publickey"), "auth_success") == 0);
    assert(strcmp(ssh_classify("Connection closed by invalid user test ::1"),
                  "connection_closed") == 0);

    return 0;
}
