#include "ssh.h"
#include "logger.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>

#define LINE_MAX_AB 4096
#define SSH_PATH_MAX 512
#define SSH_TAIL_SIZE 128

int ssh_extract_address(const char *, char *, size_t);
const char *ssh_classify(const char *);

static FILE *logf;
static char log_path[SSH_PATH_MAX];
static unsigned char tail_snapshot[SSH_TAIL_SIZE];
static size_t tail_length;
static off_t tail_offset;

static void
process_available(void)
{
    char line[LINE_MAX_AB], ip[INET6_ADDRSTRLEN];

    clearerr(logf);
    while (fgets(line, sizeof(line), logf)) {
        const char *kind = ssh_classify(line);

        if (strcmp(kind, "other") != 0) {
            if (ssh_extract_address(line, ip, sizeof(ip)))
                logger_log("SSH", "%s from %s", kind, ip);
            else
                logger_log("SSH", "%s (address unavailable)", kind);
        }
    }

    if (ferror(logf)) {
        clearerr(logf);
        logger_log("WARN", "SSH log read error");
    }
}

static void
save_tail_snapshot(void)
{
    off_t position = ftello(logf);
    size_t length;
    ssize_t n;

    tail_length = 0;
    if (position <= 0)
        return;

    length = position < (off_t)sizeof(tail_snapshot) ?
        (size_t)position : sizeof(tail_snapshot);
    tail_offset = position - (off_t)length;
    n = pread(fileno(logf), tail_snapshot, length, tail_offset);
    if (n == (ssize_t)length)
        tail_length = length;
}

static int
tail_snapshot_changed(void)
{
    unsigned char current[SSH_TAIL_SIZE];
    ssize_t n;

    if (tail_length == 0)
        return 0;

    n = pread(fileno(logf), current, tail_length, tail_offset);
    return n != (ssize_t)tail_length ||
        memcmp(current, tail_snapshot, tail_length) != 0;
}

int
ssh_init(const char *path)
{
    FILE *new_log;

    if (!path || strlen(path) >= sizeof(log_path))
        return -1;

    new_log = fopen(path, "r");
    if (!new_log)
        return -1;

    /* Start at EOF so old authentication records are not replayed. */
    if (fseeko(new_log, 0, SEEK_END) != 0) {
        fclose(new_log);
        return -1;
    }

    if (logf)
        fclose(logf);
    logf = new_log;
    (void)snprintf(log_path, sizeof(log_path), "%s", path);
    tail_length = 0;
    save_tail_snapshot();
    return 0;
}

static void
refresh_log_file(void)
{
    struct stat path_stat, fd_stat;
    off_t position;

    if (!logf || stat(log_path, &path_stat) != 0)
        return;

    if (fstat(fileno(logf), &fd_stat) != 0)
        return;

    /* Drain the renamed file before switching, preserving its final records. */
    if (path_stat.st_dev != fd_stat.st_dev ||
        path_stat.st_ino != fd_stat.st_ino) {
        FILE *new_log = fopen(log_path, "r");
        if (!new_log)
            return;
        process_available();
        fclose(logf);
        logf = new_log;
        tail_length = 0;
        logger_log("INFO", "SSH log rotated; following new file");
        return;
    }

    position = ftello(logf);
    if (position < 0)
        return;

    /* Detect ordinary copytruncate, including truncate-and-regrow past offset. */
    if (path_stat.st_size < position || tail_snapshot_changed()) {
        clearerr(logf);
        if (fseeko(logf, 0, SEEK_SET) == 0) {
            tail_length = 0;
            logger_log("INFO", "SSH log rewritten or truncated; reading from beginning");
        }
    }
}

int
ssh_process(void)
{
    if (!logf)
        return;

    refresh_log_file();
    process_available();
    save_tail_snapshot();
}

void
ssh_shutdown(void)
{
    if (logf)
        fclose(logf);
    logf = NULL;
    log_path[0] = '\0';
    tail_length = 0;
}
