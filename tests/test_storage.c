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
    assert(storage_load_temporary(got, 2, &count) == 0 && count == 2);
    assert(strcmp(got[0].ip, temp[0].ip) == 0);
    assert(got[0].expires_at == temp[0].expires_at);
    assert(strcmp(got[1].ip, temp[1].ip) == 0);
    assert(got[1].expires_at == temp[1].expires_at);


    /* A failed directory fsync happens after rename: the new file is visible,
     * and the API must report committed-but-durability-uncertain (-2). */
    {
        char uncertain[4][STORAGE_IP_LEN];
        snprintf(uncertain[0], sizeof(uncertain[0]), "203.0.113.77");
        storage_test_fail_directory_fsync(1);
        assert(storage_save_permanent((const char (*)[STORAGE_IP_LEN])uncertain, 1) == -2);
        storage_test_fail_directory_fsync(0);
        assert(storage_load_permanent(loaded, 4, &count) == 0 && count == 1);
        assert(strcmp(loaded[0], uncertain[0]) == 0);
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
    puts("PASS: storage permissions, IPv4/IPv6 lists, UTC expiry, atomic replacement and validation");
    return 0;
}
