#include "ssh.h"
#include "logger.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

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

static int count_text(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    char line[1024];
    int count = 0;

    assert(f != NULL);
    while (fgets(line, sizeof(line), f))
        if (strstr(line, needle) != NULL)
            count++;
    fclose(f);
    return count;
}

int main(void)
{
    char dir[] = "/tmp/airbotz-ssh-test.XXXXXX";
    char log_path[512], rotated_path[512], missing_path[512], output_path[512];
    const char *event1 =
        "sshd: Failed password for root from 192.0.2.1 port 22 ssh2\n";
    const char *event2 =
        "sshd: Failed password for root from 192.0.2.2 port 22 ssh2\n";
    const char *event3 =
        "sshd: Failed password for root from 192.0.2.3 port 22 ssh2\n";
    const char *long_event =
        "sshd: Failed password for deliberately-very-long-test-account-name-"
        "to-force-a-large-file-offset from 192.0.2.4 port 22 ssh2\n";
    const char *short_event =
        "sshd: Failed password for x from 192.0.2.5 port 22 ssh2\\n";
    const char *regrown_event =
        "sshd: Failed password for rewritten-"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        " from 192.0.2.6 port 22 ssh2\\n";
    const char *event4 =
        "sshd: Failed password for root from 192.0.2.7 port 22 ssh2\\n";
    int fd;

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
    assert(ssh_init(log_path) == 0);
    assert(count_text(output_path, "auth_failure from") == 0);

    write_file(log_path, event1, 1);
    ssh_process();
    assert(count_text(output_path, "auth_failure from") == 1);
    ssh_process();
    assert(count_text(output_path, "auth_failure from") == 1);

    /* Drain pending records from the renamed file before following its replacement. */
    write_file(log_path, event2, 1);
    assert(rename(log_path, rotated_path) == 0);
    write_file(log_path, event4, 0);
    ssh_process();
    assert(count_text(output_path, "auth_failure from") == 4);

    /* A temporarily missing pathname must recover when a new file appears. */
    assert(rename(log_path, missing_path) == 0);
    ssh_process();
    write_file(log_path, event3, 0);
    ssh_process();
    assert(count_text(output_path, "auth_failure from") == 3);

    /*
     * copytruncate: append and consume a long record first, then truncate
     * the same inode to a shorter record so size < previous read offset.
     */
    write_file(log_path, long_event, 1);
    ssh_process();
    assert(count_text(output_path, "auth_failure from") == 5);
    write_file(log_path, short_event, 0);
    ssh_process();
    assert(count_text(output_path, "auth_failure from") == 6);
    ssh_process();
    assert(count_text(output_path, "auth_failure from") == 6);

    /* Truncate and regrow beyond the old offset between polls. */
    write_file(log_path, long_event, 1);
    ssh_process();
    assert(count_text(output_path, "auth_failure from") == 7);
    assert(strlen(regrown_event) > strlen(short_event) + strlen(long_event));
    write_file(log_path, regrown_event, 0);
    ssh_process();
    assert(count_text(output_path, "auth_failure from") == 8);

    ssh_shutdown();
    logger_close();

    assert(unlink(log_path) == 0);
    assert(unlink(rotated_path) == 0);
    assert(unlink(missing_path) == 0);
    assert(unlink(output_path) == 0);
    assert(rmdir(dir) == 0);
    puts("PASS: SSH log initial offset, append, rename drain, missing-path recovery and copytruncate/regrowth");
    return 0;
}
