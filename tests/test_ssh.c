#include <assert.h>
#include <string.h>
#include <stddef.h>
#include "ssh_parser.h"

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


    {
        struct ssh_event event;
        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user webmaster from 192.0.2.10 port 49811 ssh2",
            &event) == 0);
        assert(event.type == SSH_EVENT_FAILED_PASSWORD);
        assert(strcmp(event.timestamp, "Dec 10 06:55:46") == 0);
        assert(strcmp(event.hostname, "LabSZ") == 0);
        assert(strcmp(event.pid, "24200") == 0);
        assert(strcmp(event.username, "webmaster") == 0);
        assert(strcmp(event.address, "192.0.2.10") == 0);
        assert(event.port == 49811 && event.has_port);
        assert(event.invalid_user);

        assert(ssh_parse_record(
            "Jan 07 17:22:01 LabSZ sshd-session[314]: Accepted publickey for jmzhu from 2001:db8::1 port 22 ssh2",
            &event) == 0);
        assert(event.type == SSH_EVENT_ACCEPTED_PUBLICKEY);
        assert(strcmp(event.username, "jmzhu") == 0);
        assert(strcmp(event.address, "2001:db8::1") == 0);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Failed none for invalid user test from 198.51.100.2 port 22 ssh2",
            &event) == 0);
        assert(event.type == SSH_EVENT_FAILED_NONE);
        assert(event.invalid_user);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Received disconnect from 203.0.113.8: 11: Bye Bye [preauth]",
            &event) == 0);
        assert(event.type == SSH_EVENT_RECEIVED_DISCONNECT);
        assert(strcmp(event.address, "203.0.113.8") == 0);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Disconnecting: Too many authentication failures for root [preauth]",
            &event) == 0);
        assert(event.type == SSH_EVENT_SERVER_DISCONNECT);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:session): session opened for user jmzhu by (uid=0)",
            &event) == 0);
        assert(event.type == SSH_EVENT_SESSION_OPENED);
        assert(strcmp(event.username, "jmzhu") == 0);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Server listening on 0.0.0.0 port 22.",
            &event) == 0);
        assert(event.type == SSH_EVENT_UNKNOWN);
        assert(event.message[0] != '\\0');

        assert(ssh_parse_record("not a syslog record", &event) == -1);
    }

    return 0;
}
