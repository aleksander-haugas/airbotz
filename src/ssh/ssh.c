#include "ssh.h"
#include "logger.h"
#include "ssh_parser.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#define SSH_PATH_MAX 512
#define SSH_TAIL_SIZE 128
#define SSH_RECORD_MAX 4096

static FILE *logf;
static char log_path[SSH_PATH_MAX];
static unsigned char tail_snapshot[SSH_TAIL_SIZE];
static size_t tail_length;
static off_t tail_offset;
static ssh_event_handler event_handler;
static void *event_context;
static unsigned char record_buffer[SSH_RECORD_MAX];
static size_t record_length;
static int dropping_record;

static void
dispatch_record(const unsigned char *record, size_t length)
{
    struct ssh_event event;

    if (ssh_parse_record_n(record, length, &event) != 0)
        return;

    if (event_handler)
        event_handler(&event, event_context);
}

static void
reset_record_buffer(void)
{
    record_length = 0;
    dropping_record = 0;
}

static void
dispatch_pending_record(void)
{
    if (!dropping_record && record_length != 0)
        dispatch_record(record_buffer, record_length);
    else if (dropping_record)
        logger_log("WARN", "SSH log record exceeded parser limit; discarded");
    reset_record_buffer();
}

/*
 * Consume complete newline-delimited records only. A partial final line is
 * retained across polls and is flushed only when the file is rotated or the
 * reader shuts down. Oversized records are discarded through their newline,
 * preventing their suffix from being misinterpreted as a new syslog record.
 */
static void
process_available(void)
{
    int ch;

    clearerr(logf);
    while ((ch = fgetc(logf)) != EOF) {
        if (ch == '\n') {
            if (!dropping_record && record_length != 0)
                dispatch_record(record_buffer, record_length);
            else if (dropping_record)
                logger_log("WARN", "SSH log record exceeded parser limit; discarded");
            reset_record_buffer();
            continue;
        }

        if (dropping_record)
            continue;
        if (record_length == sizeof(record_buffer)) {
            dropping_record = 1;
            record_length = 0;
            continue;
        }
        record_buffer[record_length++] = (unsigned char)ch;
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
ssh_init(const char *path, ssh_event_handler handler, void *context)
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
    event_handler = handler;
    event_context = context;
    reset_record_buffer();
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
        dispatch_pending_record();
        fclose(logf);
        logf = new_log;
        reset_record_buffer();
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
            reset_record_buffer();
            tail_length = 0;
            logger_log("INFO", "SSH log rewritten or truncated; reading from beginning");
        }
    }
}

void
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
    if (logf) {
        process_available();
        dispatch_pending_record();
        fclose(logf);
    }
    logf = NULL;
    event_handler = NULL;
    event_context = NULL;
    reset_record_buffer();
    log_path[0] = '\0';
    tail_length = 0;
}
