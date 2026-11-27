#include "ipc.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

static int
test_handler(const char *request, char *response, size_t size, void *context)
{
    (void)context;
    if (strcmp(request, "PING") != 0)
        return -1;
    if (snprintf(response, size, "OK pong\n") >= (int)size)
        return -1;
    return 0;
}


static int
test_incomplete_client(const char *path, int send_partial)
{
    int fd;
    struct sockaddr_un address;
    char response[32];
    ssize_t n;
    struct timeval timeout = {3, 0};

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0) {
        close(fd);
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    if (send_partial) {
        if (write(fd, "PIN", 3) != 3 || shutdown(fd, SHUT_WR) != 0) {
            close(fd);
            return -1;
        }
    }
    do {
        n = read(fd, response, sizeof(response));
    } while (n < 0 && errno == EINTR);
    close(fd);
    return n == 0 ? 0 : -1;
}


static int
test_malformed_client(const char *path, int split_terminator)
{
    int fd;
    struct sockaddr_un address;
    char response[32];
    struct timeval timeout = {3, 0};
    struct timespec delay = {0, 50000000L};
    ssize_t n;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0) {
        close(fd);
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }

    if (split_terminator) {
        if (write(fd, "PING\n", 5) != 5) {
            close(fd);
            return -1;
        }
        (void)nanosleep(&delay, NULL);
        if (write(fd, "EXTRA", 5) != 5) {
            close(fd);
            return -1;
        }
    } else if (write(fd, "PING\nPING\n", 10) != 10) {
        close(fd);
        return -1;
    }
    (void)shutdown(fd, SHUT_WR);
    do {
        n = read(fd, response, sizeof(response));
    } while (n < 0 && errno == EINTR);
    close(fd);
    return n == 0 ? 0 : -1;
}


static int
test_abrupt_disconnect(const char *path)
{
    int fd;
    struct sockaddr_un address;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    if (write(fd, "PIN", 3) != 3) {
        close(fd);
        return -1;
    }
    close(fd); /* Disconnect without completing the request. */
    return 0;
}

static int
test_simultaneous_clients(const char *path)
{
    enum { CLIENTS = 4 };
    int fds[CLIENTS];
    struct sockaddr_un address;
    struct timeval timeout = {3, 0};
    char response[32];
    ssize_t n;
    int i;

    for (i = 0; i < CLIENTS; i++) fds[i] = -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);

    for (i = 0; i < CLIENTS; i++) {
        fds[i] = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fds[i] < 0) goto fail;
        if (setsockopt(fds[i], SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout)) != 0 ||
            connect(fds[i], (struct sockaddr *)&address, sizeof(address)) != 0 ||
            write(fds[i], "PING\\n", 5) != 5 ||
            shutdown(fds[i], SHUT_WR) != 0)
            goto fail;
    }

    for (i = 0; i < CLIENTS; i++) {
        size_t used = 0;
        while (used < sizeof(response) - 1) {
            do {
                n = read(fds[i], response + used,
                         sizeof(response) - 1 - used);
            } while (n < 0 && errno == EINTR);
            if (n < 0) goto fail;
            if (n == 0) break;
            used += (size_t)n;
        }
        response[used] = '\\0';
        if (strcmp(response, "OK pong\\n") != 0) goto fail;
        close(fds[i]);
        fds[i] = -1;
    }
    return 0;

fail:
    for (i = 0; i < CLIENTS; i++) {
        if (fds[i] >= 0) close(fds[i]);
    }
    return -1;
}

int
main(void)
{
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char response[128];
    struct stat st;
    struct timespec pause = {0, 10000000L};
    pid_t child;
    int status, i;

    if (geteuid() != 0) {
        puts("SKIP: IPC server integration test requires root");
        return 0;
    }
    snprintf(path, sizeof(path), "/tmp/airbotz-ipc-%ld.sock", (long)getpid());
    if (ipc_init(path, test_handler, NULL) != 0) {
        perror("ipc_init");
        return 1;
    }
    if (lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode) ||
        (st.st_mode & 0777) != 0600 || st.st_uid != 0) {
        fprintf(stderr, "FAIL: socket ownership or permissions\n");
        ipc_shutdown();
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        ipc_shutdown();
        return 1;
    }
    if (child == 0) {
        for (i = 0; i < 300; i++) {
            (void)ipc_process();
            (void)nanosleep(&pause, NULL);
        }
        ipc_shutdown();
        _exit(0);
    }

    if (test_incomplete_client(path, 1) != 0) {
        fprintf(stderr, "FAIL: incomplete IPC request was not closed cleanly\n");
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        ipc_shutdown();
        return 1;
    }
    if (test_incomplete_client(path, 0) != 0) {
        fprintf(stderr, "FAIL: idle IPC client was not timed out cleanly\n");
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        ipc_shutdown();
        return 1;
    }

    if (test_malformed_client(path, 0) != 0) {
        fprintf(stderr, "FAIL: multiple IPC frames were not rejected\n");
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        ipc_shutdown();
        return 1;
    }
    if (test_malformed_client(path, 1) != 0) {
        fprintf(stderr, "FAIL: trailing IPC data in a later write was not rejected\n");
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        ipc_shutdown();
        return 1;
    }

    if (test_abrupt_disconnect(path) != 0) {
        fprintf(stderr, "FAIL: abrupt client disconnect setup\n");
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        ipc_shutdown();
        return 1;
    }
    if (test_simultaneous_clients(path) != 0) {
        fprintf(stderr, "FAIL: queued simultaneous IPC clients\n");
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        ipc_shutdown();
        return 1;
    }

    if (ipc_client_request(path, "PING", response, sizeof(response)) != 0 ||
        strcmp(response, "OK pong\n") != 0) {
        fprintf(stderr, "FAIL: IPC client/server round trip: %s\n", response);
        (void)kill(child, SIGTERM);
        (void)waitpid(child, NULL, 0);
        ipc_shutdown();
        return 1;
    }
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: IPC server child did not exit cleanly\n");
        ipc_shutdown();
        return 1;
    }
    ipc_shutdown();
    puts("PASS: IPC root-only socket permissions and client/server round trip");
    return 0;
}
