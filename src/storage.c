#define _XOPEN_SOURCE 700
#include "storage.h"
#include "pf.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

static char db_dir[512];

#ifdef AIRBOTZ_STORAGE_TESTING
static int test_fail_stage;
void storage_test_fail_stage(int stage)
{
    test_fail_stage = stage;
}
static int storage_test_should_fail(int stage)
{
    return test_fail_stage == stage;
}
#else
static int storage_test_should_fail(int stage)
{
    (void)stage;
    return 0;
}
#endif

static int storage_close_fd(int fd, int stage)
{
    int rc = close(fd);
#ifdef AIRBOTZ_STORAGE_TESTING
    if (storage_test_should_fail(stage)) {
        errno = EIO;
        return -1;
    }
#else
    (void)stage;
#endif
    return rc;
}

static int storage_close_stream(FILE *stream, int stage)
{
    int rc = fclose(stream);
#ifdef AIRBOTZ_STORAGE_TESTING
    if (storage_test_should_fail(stage)) {
        errno = EIO;
        return -1;
    }
#else
    (void)stage;
#endif
    return rc;
}

static void storage_cleanup_fd(int fd)
{
    int saved = errno;
    (void)close(fd);
    errno = saved;
}

static void storage_cleanup_stream(FILE *stream)
{
    int saved = errno;
    (void)fclose(stream);
    errno = saved;
}

struct permanent_data { const char (*ips)[STORAGE_IP_LEN]; size_t count; };
struct temporary_data { const struct storage_temporary *entries; size_t count; };
static const char *permanent_name = "permanent.list";
static const char *temporary_name = "temporary.list";

static int make_path(char *out, size_t size, const char *name)
{
    int n = snprintf(out, size, "%s/%s", db_dir, name);
    return n > 0 && (size_t)n < size ? 0 : -1;
}

static int secure_file(const char *path, int create)
{
    int flags = O_RDWR;
    struct stat st;
    int fd;

#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    if (create) flags |= O_CREAT;
    fd = open(path, flags, 0600);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != geteuid() || fchmod(fd, 0600) != 0) {
        storage_cleanup_fd(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
}

int storage_init(const char *directory)
{
    struct stat st;
    size_t n;
    char path[1024];
    int fd;

    if (!directory || directory[0] != '/' ||
        (n = strlen(directory)) == 0 || n >= sizeof(db_dir))
        return -1;
    if (mkdir(directory, 0700) != 0 && errno != EEXIST)
        return -1;
    if (lstat(directory, &st) != 0 || !S_ISDIR(st.st_mode) ||
        S_ISLNK(st.st_mode) || st.st_uid != geteuid())
        return -1;
    if (chmod(directory, 0700) != 0)
        return -1;
    memcpy(db_dir, directory, n + 1);

    if (make_path(path, sizeof(path), permanent_name) != 0) return -1;
    fd = secure_file(path, 1);
    if (fd < 0) return -1;
    if (storage_close_fd(fd, STORAGE_TEST_FAIL_INIT_CLOSE) != 0) return -1;
    if (make_path(path, sizeof(path), temporary_name) != 0) return -1;
    fd = secure_file(path, 1);
    if (fd < 0) return -1;
    if (storage_close_fd(fd, STORAGE_TEST_FAIL_INIT_CLOSE) != 0) return -1;
    return 0;
}

/* Read one complete newline-terminated record without accepting
 * truncated, overlong, or binary (NUL-containing) input. */
static int read_record(FILE *f, char *line, size_t capacity)
{
    size_t used = 0;
    int ch, saw_data = 0;

    if (!f || !line || capacity < 2) {
        errno = EINVAL;
        return -1;
    }
    while ((ch = fgetc(f)) != EOF) {
        saw_data = 1;
        if (ch == '\0') {
            errno = EINVAL;
            return -1;
        }
        if (ch == '\n') {
            line[used] = '\0';
            return 1;
        }
        if (used + 1 >= capacity) {
            errno = EINVAL;
            return -1;
        }
        line[used++] = (char)ch;
    }
    if (ferror(f))
        return -1;
    if (saw_data) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int parse_expiry(const char *s, time_t *value)
{
    struct tm tmv;
    char *end;
    memset(&tmv, 0, sizeof(tmv));
    end = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    if (!end || *end != '\0') return -1;
    {
        int year = tmv.tm_year + 1900;
        int month = tmv.tm_mon + 1;
        int day = tmv.tm_mday;
        int64_t era, yoe, doy, doe, days, seconds;
        struct tm check;

        if (month < 1 || month > 12 || day < 1 || day > 31 ||
            tmv.tm_hour > 23 || tmv.tm_min > 59 || tmv.tm_sec > 59)
            return -1;
        year -= month <= 2;
        era = (year >= 0 ? year : year - 399) / 400;
        yoe = year - era * 400;
        doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
        doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        days = era * 146097 + doe - 719468;
        seconds = days * 86400 + tmv.tm_hour * 3600 + tmv.tm_min * 60 + tmv.tm_sec;
        *value = (time_t)seconds;
        if ((int64_t)*value != seconds || !gmtime_r(value, &check) ||
            check.tm_year != tmv.tm_year || check.tm_mon != tmv.tm_mon ||
            check.tm_mday != tmv.tm_mday || check.tm_hour != tmv.tm_hour ||
            check.tm_min != tmv.tm_min || check.tm_sec != tmv.tm_sec)
            return -1;
    }
    return 0;
}

int storage_load_permanent(char ips[][STORAGE_IP_LEN], size_t capacity, size_t *count)
{
    char path[1024], line[STORAGE_IP_LEN];
    FILE *f;
    size_t used = 0;
    int fd, line_rc;

    if (!count || (!ips && capacity) || make_path(path, sizeof(path), permanent_name) != 0)
        return -1;
    fd = secure_file(path, 0);
    if (fd < 0) return -1;
    f = fdopen(fd, "r");
    if (!f) { storage_cleanup_fd(fd); return -1; }
    while ((line_rc = read_record(f, line, sizeof(line))) == 1) {
        size_t len = strlen(line);
        if (!len || !pf_valid_address(line) || used >= capacity) {
            errno = EINVAL;
            storage_cleanup_stream(f);
            return -1;
        }
        memcpy(ips[used++], line, len + 1);
    }
    if (line_rc < 0) {
        storage_cleanup_stream(f);
        return -1;
    }
    if (storage_close_stream(f, STORAGE_TEST_FAIL_READ_CLOSE) != 0) return -1;
    *count = used;
    return 0;
}
int storage_load_temporary(struct storage_temporary *entries, size_t capacity, size_t *count)
{
    char path[1024], line[STORAGE_IP_LEN + 1 + 32], ip[STORAGE_IP_LEN], expiry[32], extra;
    FILE *f;
    size_t used = 0;
    int fd, line_rc;

    if (!count || (!entries && capacity) || make_path(path, sizeof(path), temporary_name) != 0)
        return -1;
    fd = secure_file(path, 0);
    if (fd < 0) return -1;
    f = fdopen(fd, "r");
    if (!f) { storage_cleanup_fd(fd); return -1; }
    while ((line_rc = read_record(f, line, sizeof(line))) == 1) {
        time_t when;
        if (sscanf(line, "%45s %31s %c", ip, expiry, &extra) != 2 ||
            !pf_valid_address(ip) || parse_expiry(expiry, &when) != 0 ||
            used >= capacity) {
            errno = EINVAL;
            storage_cleanup_stream(f);
            return -1;
        }
        snprintf(entries[used].ip, sizeof(entries[used].ip), "%s", ip);
        entries[used++].expires_at = when;
    }
    if (line_rc < 0) {
        storage_cleanup_stream(f);
        return -1;
    }
    if (storage_close_stream(f, STORAGE_TEST_FAIL_READ_CLOSE) != 0) return -1;
    *count = used;
    return 0;
}
/*
 * Returns 0 when the replacement and directory entry are durable, -1 when
 * the destination was not replaced, and -2 when rename succeeded but the
 * directory fsync failed (replacement visible, crash durability uncertain).
 */
static int atomic_writer(const char *name,
                         int (*write_data)(FILE *, const void *), const void *data)
{
    char path[1024], temp[1100];
    int fd = -1, dirfd = -1, rc = -1, saved = 0;
    FILE *f = NULL;

    if (make_path(path, sizeof(path), name) != 0 ||
        snprintf(temp, sizeof(temp), "%s/.%s.XXXXXX", db_dir, name) >= (int)sizeof(temp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

#ifdef O_DIRECTORY
    dirfd = open(db_dir, O_RDONLY | O_DIRECTORY);
#else
    dirfd = open(db_dir, O_RDONLY);
#endif
    if (dirfd < 0)
        return -1;

    fd = mkstemp(temp);
    if (fd < 0) {
        saved = errno;
        close(dirfd);
        errno = saved;
        return -1;
    }
    if (fchmod(fd, 0600) != 0) {
        saved = errno;
        close(fd);
        unlink(temp);
        close(dirfd);
        errno = saved;
        return -1;
    }
    f = fdopen(fd, "w");
    if (!f) {
        saved = errno;
        close(fd);
        unlink(temp);
        close(dirfd);
        errno = saved;
        return -1;
    }

    if (storage_test_should_fail(STORAGE_TEST_FAIL_WRITE)) {
        errno = EIO;
        saved = errno;
        (void)fclose(f);
        (void)unlink(temp);
        (void)close(dirfd);
        errno = saved;
        return -1;
    }
    if (write_data(f, data) != 0) {
        saved = errno ? errno : EIO;
        (void)fclose(f);
        (void)unlink(temp);
        (void)close(dirfd);
        errno = saved;
        return -1;
    }
    if (storage_test_should_fail(STORAGE_TEST_FAIL_FLUSH) || fflush(f) != 0) {
        if (storage_test_should_fail(STORAGE_TEST_FAIL_FLUSH)) errno = EIO;
        saved = errno ? errno : EIO;
        (void)fclose(f);
        (void)unlink(temp);
        (void)close(dirfd);
        errno = saved;
        return -1;
    }
    if (storage_test_should_fail(STORAGE_TEST_FAIL_FILE_FSYNC) || fsync(fd) != 0) {
        if (storage_test_should_fail(STORAGE_TEST_FAIL_FILE_FSYNC)) errno = EIO;
        saved = errno ? errno : EIO;
        (void)fclose(f);
        (void)unlink(temp);
        (void)close(dirfd);
        errno = saved;
        return -1;
    }
    if (storage_test_should_fail(STORAGE_TEST_FAIL_FILE_CLOSE)) {
        errno = EIO;
        saved = errno;
        (void)fclose(f);
        (void)unlink(temp);
        (void)close(dirfd);
        errno = saved;
        return -1;
    }
    if (fclose(f) != 0) {
        saved = errno ? errno : EIO;
        (void)unlink(temp);
        (void)close(dirfd);
        errno = saved;
        return -1;
    }
    f = NULL;

    if (storage_test_should_fail(STORAGE_TEST_FAIL_RENAME) || rename(temp, path) != 0) {
        if (storage_test_should_fail(STORAGE_TEST_FAIL_RENAME)) errno = EIO;
        saved = errno ? errno : EIO;
        (void)unlink(temp);
        (void)close(dirfd);
        errno = saved;
        return -1;
    }

    /* From this point onward the new file is visible: never report a
     * pre-commit failure, and callers must not roll back PF as if it were not. */
#ifdef AIRBOTZ_STORAGE_TESTING
    if (storage_test_should_fail(STORAGE_TEST_FAIL_DIRECTORY_FSYNC) ||
        fsync(dirfd) != 0) {
        if (storage_test_should_fail(STORAGE_TEST_FAIL_DIRECTORY_FSYNC)) errno = EIO;
#else
    if (fsync(dirfd) != 0) {
#endif
        saved = errno ? errno : EIO;
        (void)close(dirfd);
        errno = saved;
        return -2;
    }
#ifdef AIRBOTZ_STORAGE_TESTING
    if (storage_test_should_fail(STORAGE_TEST_FAIL_DIRECTORY_CLOSE)) {
        (void)close(dirfd);
        errno = EIO;
        saved = errno;
        errno = saved;
        return -2;
    }
#endif
    if (close(dirfd) != 0) {
        saved = errno ? errno : EIO;
        errno = saved;
        return -2;
    }
    rc = 0;
    return rc;
}

static int write_permanent(FILE *f, const void *data)
{
    const struct permanent_data *p = data;
    size_t i;
    for (i = 0; i < p->count; i++) {
        if (!pf_valid_address(p->ips[i]) || fprintf(f, "%s\n", p->ips[i]) < 0)
            return -1;
    }
    return 0;
}

static int write_temporary(FILE *f, const void *data)
{
    const struct temporary_data *p = data;
    size_t i;
    for (i = 0; i < p->count; i++) {
        struct tm tmv;
        char stamp[32];
        if (!pf_valid_address(p->entries[i].ip) ||
            !gmtime_r(&p->entries[i].expires_at, &tmv) ||
            strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0 ||
            fprintf(f, "%s %s\n", p->entries[i].ip, stamp) < 0)
            return -1;
    }
    return 0;
}

int storage_save_permanent(const char ips[][STORAGE_IP_LEN], size_t count)
{
    struct permanent_data data = {ips, count};
    if ((!ips && count) || count > STORAGE_MAX_ENTRIES) return -1;
    return atomic_writer(permanent_name, write_permanent, &data);
}

int storage_save_temporary(const struct storage_temporary *entries, size_t count)
{
    struct temporary_data data = {entries, count};
    if ((!entries && count) || count > STORAGE_MAX_ENTRIES) return -1;
    return atomic_writer(temporary_name, write_temporary, &data);
}
