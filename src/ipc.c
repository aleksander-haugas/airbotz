#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#include "ipc.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <time.h>

/* FreeBSD exposes this BSD API outside strict POSIX feature profiles. */
#if defined(__FreeBSD__)
int getpeereid(int, uid_t *, gid_t *);
#endif

#define IPC_REQUEST_SIZE 256
#define IPC_REQUEST_TIMEOUT_MS 3000

static int listen_fd = -1;
static char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static ipc_request_handler request_handler;
static void *handler_context;

static int
ipc_remaining_timeout_ms(const struct timespec *deadline)
{
    struct timespec now;
    time_t seconds;
    long nanoseconds;
    long long milliseconds;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    seconds = deadline->tv_sec - now.tv_sec;
    nanoseconds = deadline->tv_nsec - now.tv_nsec;
    if (nanoseconds < 0) {
        seconds--;
        nanoseconds += 1000000000L;
    }
    milliseconds = (long long)seconds * 1000LL +
                   (nanoseconds + 999999L) / 1000000L;
    if (milliseconds <= 0)
        return 0;
    if (milliseconds > IPC_REQUEST_TIMEOUT_MS)
        return IPC_REQUEST_TIMEOUT_MS;
    return (int)milliseconds;
}

static int
write_all(int fd, const char *data, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = write(fd, data + offset, length - offset);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        offset += (size_t)n;
    }
    return 0;
}

int
ipc_init(const char *path, ipc_request_handler handler, void *context)
{
    struct sockaddr_un address;
    struct stat st;
    mode_t old_mask;

    if (!path || !*path || strlen(path) >= sizeof(address.sun_path) ||
        !handler || geteuid() != 0)
        return -1;

    if (lstat(path, &st) == 0) {
        int probe;
        if (!S_ISSOCK(st.st_mode) || st.st_uid != 0)
            return -1;
        probe = socket(AF_UNIX, SOCK_STREAM, 0);
        if (probe < 0)
            return -1;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
        if (connect(probe, (struct sockaddr *)&address, sizeof(address)) == 0) {
            close(probe);
            return -1; /* Another daemon already owns this socket. */
        }
        if (errno != ECONNREFUSED && errno != ENOENT) {
            close(probe);
            return -1;
        }
        close(probe);
        if (unlink(path) != 0)
            return -1;
    } else if (errno != ENOENT) {
        return -1;
    }

    (void)signal(SIGPIPE, SIG_IGN);
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) return -1;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);

    old_mask = umask(077);
    if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        umask(old_mask);
        close(listen_fd);
        listen_fd = -1;
        return -1;
    }
    umask(old_mask);

    if (chmod(path, 0600) != 0 || listen(listen_fd, 8) != 0) {
        unlink(path);
        close(listen_fd);
        listen_fd = -1;
        return -1;
    }

    {
        int flags = fcntl(listen_fd, F_GETFL, 0);
        if (flags < 0 || fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            unlink(path);
            close(listen_fd);
            listen_fd = -1;
            return -1;
        }
    }

    snprintf(socket_path, sizeof(socket_path), "%s", path);
    request_handler = handler;
    handler_context = context;
    return 0;
}

int
ipc_process(void)
{
    int client_fd;
    char request[IPC_REQUEST_SIZE];
    char response[IPC_RESPONSE_SIZE];
    ssize_t n;
    uid_t peer_uid;
    gid_t peer_gid;
    size_t length;

    if (listen_fd < 0) return -1;
    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
        return -1;
    }

    if (getpeereid(client_fd, &peer_uid, &peer_gid) != 0 || peer_uid != 0) {
        close(client_fd);
        return 0;
    }
    (void)peer_gid;

    {
        struct pollfd pfd;
        size_t used = 0;
        int ready, timeout, newline_seen = 0;
        char overflow_byte;
        struct timespec deadline;
        if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
            close(client_fd);
            return 0;
        }
        deadline.tv_sec += IPC_REQUEST_TIMEOUT_MS / 1000;
        deadline.tv_nsec += (IPC_REQUEST_TIMEOUT_MS % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
        pfd.fd = client_fd;
        pfd.events = POLLIN;
        for (;;) {
            timeout = ipc_remaining_timeout_ms(&deadline);
            if (timeout <= 0) {
                close(client_fd);
                return 0; /* One absolute deadline prevents slow-client stalls. */
            }
            ready = poll(&pfd, 1, timeout);
            if (ready < 0 && errno == EINTR)
                continue;
            if (ready <= 0) {
                close(client_fd);
                return 0; /* Idle or timed-out client cannot stall the daemon. */
            }

            if (used == sizeof(request) - 1) {
                n = recv(client_fd, &overflow_byte, 1, 0);
                if (n > 0) {
                    close(client_fd); /* Request exceeds the framing limit. */
                    return 0;
                }
                if (n < 0 && errno == EINTR)
                    continue;
                if (n < 0) {
                    close(client_fd);
                    return 0;
                }
                break; /* EOF after a complete, maximum-size request. */
            }

            n = recv(client_fd, request + used,
                     sizeof(request) - 1 - used, 0);
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0) {
                close(client_fd);
                return 0;
            }
            if (n == 0)
                break; /* The client must half-close after its one request. */

            if (memchr(request + used, '\0', (size_t)n) != NULL) {
                close(client_fd);
                return 0; /* Embedded NUL is never valid framing. */
            }
            if (newline_seen) {
                close(client_fd);
                return 0; /* Reject bytes arriving after the terminator. */
            }

            {
                char *found = memchr(request + used, '\n', (size_t)n);
                if (found) {
                    if (found != request + used + n - 1) {
                        close(client_fd);
                        return 0; /* Reject trailing bytes or a second frame. */
                    }
                    newline_seen = 1;
                }
            }
            used += (size_t)n;
            request[used] = '\0';
        }

        if (!newline_seen || used == 0 || request[used - 1] != '\n') {
            close(client_fd);
            return 0;
        }
        request[used - 1] = '\0';
    }

    memset(response, 0, sizeof(response));
    if (request_handler(request, response, sizeof(response), handler_context) != 0 &&
        response[0] == '\0')
        snprintf(response, sizeof(response), "ERROR internal error\n");

    length = strnlen(response, sizeof(response));
    if (length == sizeof(response)) length = sizeof(response) - 1;
    (void)write_all(client_fd, response, length);
    close(client_fd);
    return 0;
}

void
ipc_shutdown(void)
{
    struct stat st;
    if (listen_fd >= 0) {
        close(listen_fd);
        listen_fd = -1;
    }
    if (socket_path[0] && lstat(socket_path, &st) == 0 &&
        S_ISSOCK(st.st_mode) && st.st_uid == 0)
        (void)unlink(socket_path);
    socket_path[0] = '\0';
    request_handler = NULL;
    handler_context = NULL;
}

int
ipc_client_request(const char *path, const char *request,
                   char *response, size_t response_size)
{
    int fd;
    struct sockaddr_un address;
    char message[IPC_REQUEST_SIZE];
    size_t used;
    ssize_t n;
    size_t total = 0;

    if (!path || !request || !response || response_size < 2 ||
        strlen(path) >= sizeof(address.sun_path) ||
        snprintf(message, sizeof(message), "%s\n", request) >= (int)sizeof(message))
        return -1;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        write_all(fd, message, strlen(message)) != 0) {
        close(fd);
        return -1;
    }
    (void)shutdown(fd, SHUT_WR);

    while (total < response_size - 1) {
        n = read(fd, response + total, response_size - 1 - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    used = total;
    response[used] = '\0';
    close(fd);
    return 0;
}
