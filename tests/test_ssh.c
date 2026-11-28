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

    assert(ssh_extract_address(
        "sshd-session: Connection closed by invalid user test, ::1 port 46960 [preauth]",
        ip, sizeof(ip)));
    assert(strcmp(ip, "::1") == 0);

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

        /*
         * Malformed input must not underflow the username length when the
         * text is exactly "invalid user" without a following username.
         */
        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user from 192.0.2.11 port 22 ssh2",
            &event) == 0);
        assert(event.type == SSH_EVENT_FAILED_PASSWORD);
        assert(!event.invalid_user);
        assert(strcmp(event.username, "invalid user") == 0);

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
            "Dec 10 06:55:46 LabSZ sshd[24200]: Received disconnect from 2001:db8::8: 11: Bye Bye [preauth]",
            &event) == 0);
        assert(event.type == SSH_EVENT_RECEIVED_DISCONNECT);
        assert(strcmp(event.address, "2001:db8::8") == 0);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Disconnecting: Too many authentication failures for root [preauth]",
            &event) == 0);
        assert(event.type == SSH_EVENT_SERVER_DISCONNECT);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.44",
            &event) == 0);
        assert(event.type == SSH_EVENT_PAM_AUTH_FAILURE);
        assert(strcmp(event.address, "192.0.2.44") == 0);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown",
            &event) == 0);
        assert(event.type == SSH_EVENT_PAM_CHECK_PASS);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: PAM 5 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.45",
            &event) == 0);
        assert(event.type == SSH_EVENT_PAM_FAILURE_SUMMARY);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: PAM service(sshd) ignoring max retries; 6 > 3",
            &event) == 0);
        assert(event.type == SSH_EVENT_PAM_MAX_RETRIES);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for scanner.example [198.51.100.45] failed - POSSIBLE BREAK-IN ATTEMPT!",
            &event) == 0);
        assert(event.type == SSH_EVENT_REVERSE_DNS_WARNING);
        assert(strcmp(event.address, "198.51.100.45") == 0);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Did not receive identification string from 203.0.113.45",
            &event) == 0);
        assert(event.type == SSH_EVENT_IDENTIFICATION_MISSING);
        assert(event.has_address);
        assert(strcmp(event.address, "203.0.113.45") == 0);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Did not receive identification string from 2001:db8::45 port 22",
            &event) == 0);
        assert(event.type == SSH_EVENT_IDENTIFICATION_MISSING);
        assert(event.has_address);
        assert(strcmp(event.address, "2001:db8::45") == 0);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: error: Received disconnect from 203.0.113.46: 3: Auth fail [preauth]",
            &event) == 0);
        assert(event.type == SSH_EVENT_RECEIVED_DISCONNECT);
        assert(event.severity == SSH_LOG_SEVERITY_ERROR);
        assert(strcmp(event.address, "203.0.113.46") == 0);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: fatal: Read from socket failed: Connection reset by peer [preauth]",
            &event) == 0);
        assert(event.type == SSH_EVENT_SSHD_FATAL);
        assert(event.severity == SSH_LOG_SEVERITY_FATAL);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:session): session opened for user jmzhu by (uid=0)",
            &event) == 0);
        assert(event.type == SSH_EVENT_SESSION_OPENED);
        assert(strcmp(event.username, "jmzhu") == 0);

        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Server listening on 0.0.0.0 port 22.",
            &event) == 0);
        assert(event.type == SSH_EVENT_UNKNOWN);
        assert(event.message[0] != '\0');

        assert(ssh_parse_record("not a syslog record", &event) == -1);

        /* Strict syslog envelope validation: month, day and clock ranges. */
        assert(ssh_parse_record(
            "Xan 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);
        assert(ssh_parse_record(
            "Dec 00 06:55:46 LabSZ sshd[24200]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);
        assert(ssh_parse_record(
            "Dec 32 06:55:46 LabSZ sshd[24200]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);
        assert(ssh_parse_record(
            "Feb 30 06:55:46 LabSZ sshd[24200]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);
        assert(ssh_parse_record(
            "Apr 31 06:55:46 LabSZ sshd[24200]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);
        assert(ssh_parse_record(
            "Feb 29 06:55:46 LabSZ sshd[24200]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == 0);
        assert(ssh_parse_record(
            "Dec 10 24:00:00 LabSZ sshd[24200]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);
        assert(ssh_parse_record(
            "Dec 10 06:60:00 LabSZ sshd[24200]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);
        assert(ssh_parse_record(
            "Dec 10 06:55:60 LabSZ sshd[24200]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);

        /* The process token must have a numeric, non-zero PID and exact syntax. */
        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[abc]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);
        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[0]: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);
        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]junk: Failed password for root from 192.0.2.1 port 22 ssh2",
            &event) == -1);
        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd-session[314]: Accepted publickey for jmzhu from 2001:db8::1 port 22 ssh2",
            &event) == 0);

        /* Reject embedded line breaks and overlong message bodies, not truncate them. */
        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: first line\nsecond line",
            &event) == -1);
        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: first\rline",
            &event) == -1);
        assert(ssh_parse_record(
            "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 192.0.2.1 port 22 ssh2\r\n",
            &event) == 0);
        {
            char oversized[1200];
            const char *prefix =
                "Dec 10 06:55:46 LabSZ sshd[24200]: ";
            size_t prefix_len = strlen(prefix);
            memcpy(oversized, prefix, prefix_len);
            memset(oversized + prefix_len, 'A',
                   sizeof(oversized) - prefix_len - 1);
            oversized[sizeof(oversized) - 1] = '\0';
            assert(ssh_parse_record(oversized, &event) == -1);
        }
    }

    return 0;
}
