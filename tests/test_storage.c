#include "storage.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int main(void)
{
    char dir[] = "/tmp/airbotz-storage.XXXXXX";
    char ips[4][STORAGE_IP_LEN], loaded[4][STORAGE_IP_LEN];
    struct storage_temporary temp[2], got[2];
    size_t count = 0;
    struct stat st;

    assert(mkdtemp(dir) != NULL);
    assert(rmdir(dir) == 0);
    assert(storage_init(dir) == 0);
    assert(stat(dir, &st) == 0 && (st.st_mode & 0777) == 0700);

    snprintf(ips[0], sizeof(ips[0]), "192.0.2.10");
    snprintf(ips[1], sizeof(ips[1]), "2001:db8::10");
    assert(storage_save_permanent((const char (*)[STORAGE_IP_LEN])ips, 2) == 0);
    assert(storage_load_permanent(loaded, 4, &count) == 0 && count == 2);
    assert(strcmp(loaded[0], ips[0]) == 0 && strcmp(loaded[1], ips[1]) == 0);

    snprintf(temp[0].ip, sizeof(temp[0].ip), "198.51.100.7");
    temp[0].expires_at = 1795737600; /* 2026-11-27T00:00:00Z */
    snprintf(temp[1].ip, sizeof(temp[1].ip), "2001:db8::20");
    temp[1].expires_at = 1795824000;
    assert(storage_save_temporary(temp, 2) == 0);
    /* A successful read followed by a close error must not be reported
     * as a successful load or publish a new count. */
    storage_test_fail_stage(STORAGE_TEST_FAIL_READ_CLOSE);
    assert(storage_load_permanent(loaded, 4, &count) == -1);
    storage_test_fail_stage(STORAGE_TEST_FAIL_NONE);
    assert(storage_load_permanent(loaded, 4, &count) == 0 && count == 2);

    assert(storage_load_temporary(got, 2, &count) == 0 && count == 2);
    assert(strcmp(got[0].ip, temp[0].ip) == 0);
    assert(got[0].expires_at == temp[0].expires_at);
    assert(strcmp(got[1].ip, temp[1].ip) == 0);
    assert(got[1].expires_at == temp[1].expires_at);


    /* Every injected pre-rename failure must preserve the old destination. */
    {
        char candidate[1][STORAGE_IP_LEN];
        int stage;
        snprintf(candidate[0], sizeof(candidate[0]), "203.0.113.77");
        for (stage = STORAGE_TEST_FAIL_WRITE; stage <= STORAGE_TEST_FAIL_RENAME; stage++) {
            storage_test_fail_stage(stage);
            assert(storage_save_permanent((const char (*)[STORAGE_IP_LEN])candidate, 1) == -1);
            storage_test_fail_stage(STORAGE_TEST_FAIL_NONE);
            assert(storage_load_permanent(loaded, 4, &count) == 0 && count == 2);
            assert(strcmp(loaded[0], ips[0]) == 0 && strcmp(loaded[1], ips[1]) == 0);
        }

        /* Directory fsync/close errors occur after rename: the replacement is
         * visible, but the result must explicitly report uncertain durability. */
        storage_test_fail_stage(STORAGE_TEST_FAIL_DIRECTORY_FSYNC);
        assert(storage_save_permanent((const char (*)[STORAGE_IP_LEN])candidate, 1) == -2);
        storage_test_fail_stage(STORAGE_TEST_FAIL_NONE);
        assert(storage_load_permanent(loaded, 4, &count) == 0 && count == 1);
        assert(strcmp(loaded[0], candidate[0]) == 0);

        snprintf(ips[0], sizeof(ips[0]), "192.0.2.10");
        snprintf(ips[1], sizeof(ips[1]), "2001:db8::10");
        assert(storage_save_permanent((const char (*)[STORAGE_IP_LEN])ips, 2) == 0);

        storage_test_fail_stage(STORAGE_TEST_FAIL_DIRECTORY_CLOSE);
        assert(storage_save_permanent((const char (*)[STORAGE_IP_LEN])candidate, 1) == -2);
        storage_test_fail_stage(STORAGE_TEST_FAIL_NONE);
        assert(storage_load_permanent(loaded, 4, &count) == 0 && count == 1);
        assert(strcmp(loaded[0], candidate[0]) == 0);
    }

    assert(storage_save_permanent(NULL, 0) == 0);
    assert(storage_load_permanent(loaded, 4, &count) == 0 && count == 0);
    assert(storage_save_temporary(NULL, 0) == 0);
    assert(storage_load_temporary(got, 2, &count) == 0 && count == 0);

    {
        char path[512];
        FILE *f;
        snprintf(path, sizeof(path), "%s/permanent.list", dir);
        f = fopen(path, "w");
        assert(f != NULL);
        fputs("not-an-ip\n", f);
        fclose(f);
        assert(storage_load_permanent(loaded, 4, &count) == -1);
    }

    {
        char path[512];
        snprintf(path, sizeof(path), "%s/permanent.list", dir);
        assert(unlink(path) == 0);
        snprintf(path, sizeof(path), "%s/temporary.list", dir);
        assert(unlink(path) == 0);
    }
    assert(rmdir(dir) == 0);

    /* Initialization must surface close failures instead of silently
     * claiming that both persistence files were initialized successfully. */
    {
        char init_dir[] = "/tmp/airbotz-storage-init.XXXXXX";
        char path[512];
        assert(mkdtemp(init_dir) != NULL);
        assert(rmdir(init_dir) == 0);
        storage_test_fail_stage(STORAGE_TEST_FAIL_INIT_CLOSE);
        assert(storage_init(init_dir) == -1);
        storage_test_fail_stage(STORAGE_TEST_FAIL_NONE);
        snprintf(path, sizeof(path), "%s/permanent.list", init_dir);
        assert(unlink(path) == 0);
        snprintf(path, sizeof(path), "%s/temporary.list", init_dir);
        (void)unlink(path); /* The injected first close can stop initialization early. */
        assert(rmdir(init_dir) == 0);
    }
    puts("PASS: storage permissions, IPv4/IPv6 lists, UTC expiry, atomic replacement and validation");
    return 0;
}
