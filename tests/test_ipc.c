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
