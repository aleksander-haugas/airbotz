#ifndef AIRBOTZ_IPC_H
#define AIRBOTZ_IPC_H

#include <stddef.h>

#define IPC_RESPONSE_SIZE 65536

typedef int (*ipc_request_handler)(const char *request, char *response,
                                   size_t response_size, void *context);

int ipc_init(const char *path, ipc_request_handler handler, void *context);
int ipc_process(void);
void ipc_shutdown(void);
int ipc_client_request(const char *path, const char *request,
                       char *response, size_t response_size);

#endif
