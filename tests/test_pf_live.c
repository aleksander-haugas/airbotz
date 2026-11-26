#include "pf.h"
#include <stdio.h>
#include <unistd.h>

#define TEST_IP "192.0.2.10"

static int exercise_table(const char *name,
                          int (*add_fn)(const char *),
                          int (*delete_fn)(const char *)) {
    printf("Testing %s with %s\n", name, TEST_IP);
    if (add_fn(TEST_IP) != 0) {
        fprintf(stderr, "FAIL: add to %s failed\n", name);
        return -1;
    }
    if (delete_fn(TEST_IP) != 0) {
        fprintf(stderr, "FAIL: delete from %s failed; attempting cleanup\n", name);
        (void)delete_fn(TEST_IP);
        return -1;
    }
    printf("PASS: add/delete on %s\n", name);
    return 0;
}

int main(void) {
    int failed = 0;

    if (geteuid() != 0) {
        fprintf(stderr, "Run this integration test as root.\n");
        return 2;
    }
    if (pf_init("airbotz_temp", "airbotz_perm") != 0) {
        fprintf(stderr, "Could not initialize AirBotz PF table names.\n");
        return 1;
    }
    if (pf_status() != 0) {
        fprintf(stderr, "PF is unavailable or disabled.\n");
        pf_shutdown();
        return 1;
    }

    /*
     * This address must not already be present in either table.
     * It is a documentation-only TEST-NET address, not a real host.
     */
    if (exercise_table("airbotz_temp", pf_temp_add, pf_temp_delete) != 0)
        failed = 1;
    if (exercise_table("airbotz_perm", pf_perm_add, pf_perm_delete) != 0)
        failed = 1;

    pf_shutdown();
    return failed ? 1 : 0;
}
