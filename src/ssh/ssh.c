#include "ssh.h"
#include "logger.h"

#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>

#define LINE_MAX_AB 4096
#define SSH_PATH_MAX 512

int ssh_extract_address(const char *, char *, size_t);
const char *ssh_classify(const char *);

static FILE *logf;
static char log_path[SSH_PATH_MAX];

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

    /* Rename-and-create rotation: follow the new file from its beginning. */
    if (path_stat.st_dev != fd_stat.st_dev ||
        path_stat.st_ino != fd_stat.st_ino) {
        FILE *new_log = fopen(log_path, "r");
        if (!new_log)
            return;
        if (logf)
            fclose(logf);
        logf = new_log;
        logger_log("INFO", "SSH log rotated; following new file");
        return;
    }

    /* copytruncate rotation: the same file was shortened in place. */
    position = ftello(logf);
    if (position >= 0 && path_stat.st_size < position) {
        clearerr(logf);
        if (fseeko(logf, 0, SEEK_SET) == 0)
            logger_log("INFO", "SSH log truncated; reading from beginning");
    }
}

void
ssh_process(void)
{
    char line[LINE_MAX_AB], ip[INET6_ADDRSTRLEN];

    if (!logf)
        return;

    refresh_log_file();
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

void
ssh_shutdown(void)
{
    if (logf)
        fclose(logf);
    logf = NULL;
    log_path[0] = '\0';
}
