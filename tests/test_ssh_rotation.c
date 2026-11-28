#include "ssh.h"
#include "logger.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

struct observed_events {
    int failed_password;
    int total;
    char last_address[SSH_EVENT_IP_MAX];
};

static void
capture_event(const struct ssh_event *event, void *context)
{
    struct observed_events *observed = context;

    observed->total++;
    if (event->type == SSH_EVENT_FAILED_PASSWORD) {
        observed->failed_password++;
        if (event->has_address)
            snprintf(observed->last_address, sizeof(observed->last_address),
                     "%s", event->address);
    }
}

static void write_file(const char *path, const char *text, int append)
{
    int flags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);
    int fd = open(path, flags, 0600);
    size_t len = strlen(text);
    ssize_t written = 0;

    assert(fd >= 0);
    while ((size_t)written < len) {
        ssize_t n = write(fd, text + written, len - (size_t)written);
        assert(n > 0);
        written += n;
    }
    assert(close(fd) == 0);
}


int main(void)
{
    char dir[] = "/tmp/airbotz-ssh-test.XXXXXX";
    char log_path[512], rotated_path[512], missing_path[512], output_path[512];
    const char *event1 =
        "Dec 10 06:55:46 testhost sshd[1001]: Failed password for root from 192.0.2.1 port 22 ssh2\n";
    const char *event2 =
        "Dec 10 06:55:47 testhost sshd[1002]: Failed password for root from 192.0.2.2 port 22 ssh2";
    const char *event3 =
        "Dec 10 06:55:48 testhost sshd[1003]: Failed password for root from 192.0.2.3 port 22 ssh2\n";
    const char *long_event =
        "Dec 10 06:55:49 testhost sshd[1004]: Failed password for deliberately-very-long-test-account-name-"
        "to-force-a-large-file-offset from 192.0.2.4 port 22 ssh2\n";
    const char *short_event =
        "Dec 10 06:55:50 testhost sshd[1005]: Failed password for x from 192.0.2.5 port 22 ssh2\n";
    const char *regrown_event =
        "Dec 10 06:55:51 testhost sshd[1006]: Failed password for rewritten-"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        " from 192.0.2.6 port 22 ssh2\n";
    const char *event4 =
        "Dec 10 06:55:52 testhost sshd[1007]: Failed password for root from 192.0.2.7 port 22 ssh2\n";
    int fd;
    struct observed_events observed = {0, 0, ""};

    assert(mkdtemp(dir) != NULL);
    assert(snprintf(log_path, sizeof(log_path), "%s/auth.log", dir) > 0);
    assert(snprintf(rotated_path, sizeof(rotated_path), "%s/auth.log.0", dir) > 0);
    assert(snprintf(missing_path, sizeof(missing_path), "%s/auth.log.gone", dir) > 0);
    assert(snprintf(output_path, sizeof(output_path), "%s/airbotz.log", dir) > 0);

    fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    assert(close(fd) == 0);
    write_file(log_path, event1, 1); /* Existing records must not be replayed. */

    assert(logger_init(output_path) == 0);
    assert(ssh_init(log_path, capture_event, &observed) == 0);
    assert(observed.failed_password == 0);

    write_file(log_path, event1, 1);
    ssh_process();
    assert(observed.failed_password == 1);
    ssh_process();
    assert(observed.failed_password == 1);

    /* Drain pending records from the renamed file before following its replacement. */
    write_file(log_path, event2, 1);
    assert(rename(log_path, rotated_path) == 0);
    write_file(log_path, event4, 0);
    ssh_process();
    assert(observed.failed_password == 3);

    /* A temporarily missing pathname must recover when a new file appears. */
    assert(rename(log_path, missing_path) == 0);
    ssh_process();
    write_file(log_path, event3, 0);
    ssh_process();
    assert(observed.failed_password == 4);

    /*
     * copytruncate: append and consume a long record first, then truncate
     * the same inode to a shorter record so size < previous read offset.
     */
    write_file(log_path, long_event, 1);
    ssh_process();
    assert(observed.failed_password == 5);
    write_file(log_path, short_event, 0);
    ssh_process();
    assert(observed.failed_password == 6);
    ssh_process();
    assert(observed.failed_password == 6);

    /* Truncate and regrow beyond the old offset between polls. */
    write_file(log_path, long_event, 1);
    ssh_process();
    assert(observed.failed_password == 7);
    assert(strlen(regrown_event) > strlen(short_event) + strlen(long_event));
    write_file(log_path, regrown_event, 0);
    ssh_process();
    assert(observed.failed_password == 8);
    assert(strcmp(observed.last_address, "192.0.2.6") == 0);

    /* A partial record is held until its newline arrives. */
    write_file(log_path,
        "Dec 10 06:55:53 testhost sshd[1008]: Failed password for partial from 192.0.2.8 port 22 ssh2",
        1);
    ssh_process();
    assert(observed.failed_password == 8);
    write_file(log_path, "\n", 1);
    ssh_process();
    assert(observed.failed_password == 9);
    assert(strcmp(observed.last_address, "192.0.2.8") == 0);

    /* Oversized records are discarded through newline; the next record survives. */
    {
        char oversized[5000];
        const char *prefix =
            "Dec 10 06:55:54 testhost sshd[1009]: ";
        const char *next =
            "\nDec 10 06:55:55 testhost sshd[1010]: Failed password for next from 192.0.2.9 port 22 ssh2\n";
        size_t prefix_len = strlen(prefix);
        size_t next_len = strlen(next);
        memset(oversized, 'X', sizeof(oversized));
        memcpy(oversized, prefix, prefix_len);
        memcpy(oversized + sizeof(oversized) - next_len,
               next, next_len);
        oversized[sizeof(oversized) - 1] = '\0';
        write_file(log_path, oversized, 1);
        ssh_process();
        assert(observed.failed_password == 10);
        assert(strcmp(observed.last_address, "192.0.2.9") == 0);
    }

    ssh_shutdown();
    logger_close();

    assert(unlink(log_path) == 0);
    assert(unlink(rotated_path) == 0);
    assert(unlink(missing_path) == 0);
    assert(unlink(output_path) == 0);
    assert(rmdir(dir) == 0);
    puts("PASS: SSH parser dispatch, initial offset, append, rename drain, missing-path recovery and copytruncate/regrowth");
    return 0;
}
