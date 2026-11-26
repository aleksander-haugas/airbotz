#include "core.h"
#include "ipc.h"
#include "config.h"

#include <stdio.h>
#include <string.h>

static int
run_client(int argc, char **argv, const char *config_path)
{
    char request[256], response[IPC_RESPONSE_SIZE];
    struct ab_config cfg;
    int n, first = 1;

    if (config_load(config_path, &cfg) != 0) {
        fprintf(stderr, "Cannot read AirBotz configuration: %s\n", config_path);
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "-c") == 0)
        first = 3;
    argc -= first - 1;
    argv += first - 1;

    if (argc == 2 && strcmp(argv[1], "status") == 0) {
        snprintf(request, sizeof(request), "STATUS");
    } else if (argc == 3 && strcmp(argv[1], "ip") == 0 &&
               strcmp(argv[2], "list") == 0) {
        snprintf(request, sizeof(request), "LIST");
    } else if (argc == 5 && strcmp(argv[1], "ip") == 0 &&
               strcmp(argv[2], "add") == 0 &&
               strcmp(argv[4], "permanent") == 0) {
        n = snprintf(request, sizeof(request), "ADD_PERM %s permanent", argv[3]);
        if (n < 0 || (size_t)n >= sizeof(request)) return 2;
    } else if (argc == 6 && strcmp(argv[1], "ip") == 0 &&
               strcmp(argv[2], "add") == 0 &&
               strcmp(argv[4], "temporary") == 0) {
        n = snprintf(request, sizeof(request), "ADD_TEMP %s temporary %s",
                     argv[3], argv[5]);
        if (n < 0 || (size_t)n >= sizeof(request)) return 2;
    } else if (argc == 5 && strcmp(argv[1], "ip") == 0 &&
               strcmp(argv[2], "remove") == 0 &&
               strcmp(argv[4], "permanent") == 0) {
        n = snprintf(request, sizeof(request), "DEL_PERM %s permanent", argv[3]);
        if (n < 0 || (size_t)n >= sizeof(request)) return 2;
    } else if (argc == 5 && strcmp(argv[1], "ip") == 0 &&
               strcmp(argv[2], "remove") == 0 &&
               strcmp(argv[4], "temporary") == 0) {
        n = snprintf(request, sizeof(request), "DEL_TEMP %s temporary", argv[3]);
        if (n < 0 || (size_t)n >= sizeof(request)) return 2;
    } else {
        fprintf(stderr,
            "Usage:\n"
            "  %s [-c config]\n"
            "  %s status\n"
            "  %s ip list\n"
            "  %s ip add <address> permanent\n"
            "  %s ip add <address> temporary <seconds>\n"
            "  %s ip remove <address> permanent|temporary\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 2;
    }

    if (ipc_client_request(cfg.socket_path, request,
                           response, sizeof(response)) != 0) {
        fprintf(stderr, "AirBotz daemon unavailable or control socket inaccessible\n");
        return 1;
    }
    fputs(response, stdout);
    return strncmp(response, "OK", 2) == 0 ? 0 : 1;
}

int
main(int argc, char **argv)
{
    const char *config = "config/airbotz.conf";
    if (argc > 1 && argv[1][0] != '-')
        return run_client(argc, argv, config);
    if (argc >= 4 && strcmp(argv[1], "-c") == 0)
        return run_client(argc, argv, argv[2]);
    if (argc == 3 && strcmp(argv[1], "-c") == 0) config = argv[2];
    else if (argc != 1) {
        fprintf(stderr, "Usage: %s [-c config]\n", argv[0]);
        return 2;
    }
    if (core_init(config) != 0) {
        fprintf(stderr, "AirBotz initialization failed\n");
        return 1;
    }
    core_run();
    core_shutdown();
    return 0;
}
