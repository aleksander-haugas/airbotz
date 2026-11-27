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

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
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
