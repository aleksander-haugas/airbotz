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

static char db_dir[512];

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
        close(fd);
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
    close(fd);
    if (make_path(path, sizeof(path), temporary_name) != 0) return -1;
    fd = secure_file(path, 1);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

static int parse_expiry(const char *s, time_t *value)
{
    struct tm tmv;
    char *end;
    memset(&tmv, 0, sizeof(tmv));
    end = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    if (!end || *end != '\0') return -1;
    tmv.tm_isdst = 0;
    *value = timegm(&tmv);
    return *value == (time_t)-1 ? -1 : 0;
}

int storage_load_permanent(char ips[][STORAGE_IP_LEN], size_t capacity, size_t *count)
{
    char path[1024], line[256];
    FILE *f;
    size_t used = 0;
    int fd;

    if (!count || (!ips && capacity) || make_path(path, sizeof(path), permanent_name) != 0)
        return -1;
    fd = secure_file(path, 0);
    if (fd < 0) return -1;
    f = fdopen(fd, "r");
    if (!f) { close(fd); return -1; }
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len && line[len - 1] == '\n') line[--len] = '\0';
        if (!len || len >= STORAGE_IP_LEN || !pf_valid_address(line) ||
            used >= capacity) { fclose(f); return -1; }
        memcpy(ips[used++], line, len + 1);
    }
    if (ferror(f)) { fclose(f); return -1; }
    fclose(f);
    *count = used;
    return 0;
}

int storage_load_temporary(struct storage_temporary *entries, size_t capacity, size_t *count)
{
    char path[1024], line[256], ip[STORAGE_IP_LEN], expiry[32], extra;
    FILE *f;
    size_t used = 0;
    int fd;

    if (!count || (!entries && capacity) || make_path(path, sizeof(path), temporary_name) != 0)
        return -1;
    fd = secure_file(path, 0);
    if (fd < 0) return -1;
    f = fdopen(fd, "r");
    if (!f) { close(fd); return -1; }
    while (fgets(line, sizeof(line), f)) {
        time_t when;
        if (sscanf(line, "%45s %31s %c", ip, expiry, &extra) != 2 ||
            !pf_valid_address(ip) || parse_expiry(expiry, &when) != 0 ||
            used >= capacity) { fclose(f); return -1; }
        snprintf(entries[used].ip, sizeof(entries[used].ip), "%s", ip);
        entries[used++].expires_at = when;
    }
    if (ferror(f)) { fclose(f); return -1; }
    fclose(f);
    *count = used;
    return 0;
}

static int atomic_writer(const char *name,
                         int (*write_data)(FILE *, const void *), const void *data)
{
    char path[1024], temp[1100];
    int fd, rc, saved;
    FILE *f;

    if (make_path(path, sizeof(path), name) != 0 ||
        snprintf(temp, sizeof(temp), "%s/.%s.XXXXXX", db_dir, name) >= (int)sizeof(temp))
        return -1;
    fd = mkstemp(temp);
    if (fd < 0) return -1;
    if (fchmod(fd, 0600) != 0 || (f = fdopen(fd, "w")) == NULL) {
        saved = errno; close(fd); unlink(temp); errno = saved; return -1;
    }
    rc = write_data(f, data);
    if (rc == 0 && fflush(f) != 0) rc = -1;
    if (rc == 0 && fsync(fd) != 0) rc = -1;
    saved = errno;
    if (fclose(f) != 0) rc = -1;
    if (rc == 0 && rename(temp, path) != 0) rc = -1;
    if (rc == 0) {
        int dfd = open(db_dir, O_RDONLY);
        if (dfd >= 0) { if (fsync(dfd) != 0) rc = -1; close(dfd); }
    }
    if (rc != 0) unlink(temp);
    errno = saved;
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
