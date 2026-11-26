#include "address_manager.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char fake_perm[8][STORAGE_IP_LEN];
static char fake_temp[8][STORAGE_IP_LEN];
static size_t fake_perm_count, fake_temp_count;
static int fail_perm_add, fail_perm_delete, fail_temp_add, fail_temp_delete;
static size_t temp_delete_calls, fail_temp_delete_on_call;

static int add_to(char list[][STORAGE_IP_LEN], size_t *count, const char *ip)
{
    size_t i;
    for (i = 0; i < *count; i++) if (!strcmp(list[i], ip)) return 0;
    if (*count >= 8) return -1;
    snprintf(list[(*count)++], STORAGE_IP_LEN, "%s", ip);
    return 0;
}
static int del_from(char list[][STORAGE_IP_LEN], size_t *count, const char *ip)
{
    size_t i;
    for (i = 0; i < *count; i++) if (!strcmp(list[i], ip)) break;
    if (i == *count) return 0;
    memmove(&list[i], &list[i + 1], (*count - i - 1) * STORAGE_IP_LEN);
    (*count)--;
    return 0;
}
static int p_add(const char *ip) { if (fail_perm_add) return -1; return add_to(fake_perm, &fake_perm_count, ip); }
static int p_del(const char *ip) { if (fail_perm_delete) return -1; return del_from(fake_perm, &fake_perm_count, ip); }
static int t_add(const char *ip) { if (fail_temp_add) return -1; return add_to(fake_temp, &fake_temp_count, ip); }
static int t_del(const char *ip) { temp_delete_calls++; if (fail_temp_delete || (fail_temp_delete_on_call && temp_delete_calls == fail_temp_delete_on_call)) return -1; return del_from(fake_temp, &fake_temp_count, ip); }

int main(void)
{
    char dir[] = "/tmp/airbotz-manager.XXXXXX";
    static struct address_manager manager, reloaded;
    struct address_manager_ops ops = {t_add, t_del, p_add, p_del};
    size_t expired = 0;
    time_t now = time(NULL);

    assert(mkdtemp(dir) != NULL);
    assert(rmdir(dir) == 0);
    assert(storage_init(dir) == 0);
    assert(address_manager_init(&manager, &ops, 1) == 0);
    assert(address_manager_add_permanent(&manager, "192.0.2.10") == 0);
    assert(address_manager_add_permanent(&manager, "192.0.2.10") == 0);
    assert(manager.permanent_count == 1 && fake_perm_count == 1);
    assert(address_manager_add_temporary(&manager, "2001:db8::10", now + 60) == 0);
    assert(manager.temporary_count == 1 && fake_temp_count == 1);
    assert(address_manager_add_temporary(&manager, "2001:db8::10", now + 120) == 0);
    assert(manager.temporary_count == 1 && manager.temporary[0].expires_at == now + 120);

    assert(address_manager_init(&reloaded, &ops, 1) == 0);
    assert(reloaded.permanent_count == 1 && reloaded.temporary_count == 1);
    assert(address_manager_restore(&reloaded) == 0);


    /* Post-rename directory-fsync failure is committed: do not roll PF back,
     * and keep memory aligned with the visible replacement. */
    {
        storage_test_fail_stage(STORAGE_TEST_FAIL_DIRECTORY_FSYNC);
        assert(address_manager_add_permanent(&manager, "203.0.113.88") == -3);
        storage_test_fail_stage(STORAGE_TEST_FAIL_NONE);
        assert(manager.permanent_count == 2);
        assert(fake_perm_count == 2);
        assert(!strcmp(manager.permanent[1], "203.0.113.88"));
        assert(storage_load_permanent(manager.permanent, STORAGE_MAX_ENTRIES,
                                      &manager.permanent_count) == 0);
        assert(manager.permanent_count == 2);
        assert(address_manager_delete_permanent(&manager, "203.0.113.88") == 0);
    }

    fail_perm_add = 1;
    assert(address_manager_add_permanent(&manager, "198.51.100.2") == -1);
    fail_perm_add = 0;
    assert(manager.permanent_count == 1);

    {
        char moved[512];
        snprintf(moved, sizeof(moved), "%s.moved", dir);
        assert(rename(dir, moved) == 0);
        assert(address_manager_add_permanent(&manager, "198.51.100.3") == -1);
        assert(manager.permanent_count == 1 && fake_perm_count == 1);
        assert(rename(moved, dir) == 0);
    }

    fail_temp_delete = 1;
    assert(address_manager_delete_temporary(&manager, "2001:db8::10") == -1);
    fail_temp_delete = 0;
    assert(manager.temporary_count == 1);

    /* Storage failure after each PF mutation must roll PF back while memory
     * remains unchanged. The directory is moved only for the operation. */
    {
        char moved[512];
        snprintf(moved, sizeof(moved), "%s.rollback", dir);

        assert(rename(dir, moved) == 0);
        assert(address_manager_add_permanent(&manager, "198.51.100.20") == -1);
        assert(rename(moved, dir) == 0);
        assert(manager.permanent_count == 1 && fake_perm_count == 1);

        assert(rename(dir, moved) == 0);
        assert(address_manager_delete_permanent(&manager, "192.0.2.10") == -1);
        assert(rename(moved, dir) == 0);
        assert(manager.permanent_count == 1 && fake_perm_count == 1);

        assert(rename(dir, moved) == 0);
        assert(address_manager_add_temporary(&manager, "2001:db8::20", now + 300) == -1);
        assert(rename(moved, dir) == 0);
        assert(manager.temporary_count == 1 && fake_temp_count == 1);

        assert(rename(dir, moved) == 0);
        assert(address_manager_delete_temporary(&manager, "2001:db8::10") == -1);
        assert(rename(moved, dir) == 0);
        assert(manager.temporary_count == 1 && fake_temp_count == 1);
    }

    /* If the compensating PF operation also fails, return -2 and leave the
     * discrepancy visible to the caller instead of claiming a clean rollback. */
    {
        char moved[512];
        snprintf(moved, sizeof(moved), "%s.rollback-fail", dir);

        assert(rename(dir, moved) == 0);
        fail_perm_delete = 1;
        assert(address_manager_add_permanent(&manager, "198.51.100.21") == -2);
        fail_perm_delete = 0;
        assert(rename(moved, dir) == 0);
        assert(manager.permanent_count == 1 && fake_perm_count == 2);
        assert(p_del("198.51.100.21") == 0);
        assert(fake_perm_count == 1);

        assert(rename(dir, moved) == 0);
        fail_perm_add = 1;
        assert(address_manager_delete_permanent(&manager, "192.0.2.10") == -2);
        fail_perm_add = 0;
        assert(rename(moved, dir) == 0);
        assert(manager.permanent_count == 1 && fake_perm_count == 0);
        assert(p_add("192.0.2.10") == 0);

        assert(rename(dir, moved) == 0);
        fail_temp_delete = 1;
        assert(address_manager_add_temporary(&manager, "2001:db8::21", now + 300) == -2);
        fail_temp_delete = 0;
        assert(rename(moved, dir) == 0);
        assert(manager.temporary_count == 1 && fake_temp_count == 2);
        assert(t_del("2001:db8::21") == 0);

        assert(rename(dir, moved) == 0);
        fail_temp_add = 1;
        assert(address_manager_delete_temporary(&manager, "2001:db8::10") == -2);
        fail_temp_add = 0;
        assert(rename(moved, dir) == 0);
        assert(manager.temporary_count == 1 && fake_temp_count == 0);
        assert(t_add("2001:db8::10") == 0);
    }

    assert(address_manager_expire(&manager, now + 121, &expired) == 0);
    assert(expired == 1 && manager.temporary_count == 0 && fake_temp_count == 0);
    assert(address_manager_delete_permanent(&manager, "192.0.2.10") == 0);
    assert(manager.permanent_count == 0 && fake_perm_count == 0);

    {
        struct storage_temporary expired_entry;
        snprintf(expired_entry.ip, sizeof(expired_entry.ip), "203.0.113.9");
        expired_entry.expires_at = now - 1;
        assert(storage_save_temporary(&expired_entry, 1) == 0);
        assert(t_add(expired_entry.ip) == 0);
        assert(address_manager_init(&reloaded, &ops, 1) == 0);
        assert(address_manager_restore(&reloaded) == 0);
        assert(reloaded.temporary_count == 0 && fake_temp_count == 0);
    }

    /* Restore must finish reapplying live PF entries even when pruning
     * expired entries committed with uncertain directory durability. */
    {
        struct storage_temporary entries[2];
        char permanent[1][STORAGE_IP_LEN];

        snprintf(permanent[0], sizeof(permanent[0]), "203.0.113.44");
        snprintf(entries[0].ip, sizeof(entries[0].ip), "203.0.113.9");
        entries[0].expires_at = now - 1;
        snprintf(entries[1].ip, sizeof(entries[1].ip), "203.0.113.10");
        entries[1].expires_at = now + 300;
        assert(storage_save_permanent((const char (*)[STORAGE_IP_LEN])permanent, 1) == 0);
        assert(storage_save_temporary(entries, 2) == 0);
        assert(t_add(entries[0].ip) == 0);

        storage_test_fail_stage(STORAGE_TEST_FAIL_DIRECTORY_FSYNC);
        assert(address_manager_init(&reloaded, &ops, 1) == 0);
        assert(address_manager_restore(&reloaded) == -3);
        storage_test_fail_stage(STORAGE_TEST_FAIL_NONE);

        assert(reloaded.permanent_count == 1);
        assert(reloaded.temporary_count == 1);
        assert(fake_perm_count == 1 && !strcmp(fake_perm[0], permanent[0]));
        assert(fake_temp_count == 1 && !strcmp(fake_temp[0], entries[1].ip));
    }

    /* A partial startup restore must not delete entries already present in
     * PF: the manager cannot distinguish pre-existing table members from
     * entries added by this restore. Keep the partial state and allow an
     * idempotent retry after the transient PF failure is cleared. */
    {
        char permanent[2][STORAGE_IP_LEN];
        struct storage_temporary entries[2];

        snprintf(permanent[0], sizeof(permanent[0]), "198.51.100.40");
        snprintf(permanent[1], sizeof(permanent[1]), "198.51.100.41");
        snprintf(entries[0].ip, sizeof(entries[0].ip), "2001:db8::40");
        entries[0].expires_at = now + 300;
        snprintf(entries[1].ip, sizeof(entries[1].ip), "2001:db8::41");
        entries[1].expires_at = now + 300;
        assert(storage_save_permanent((const char (*)[STORAGE_IP_LEN])permanent, 2) == 0);
        assert(storage_save_temporary(entries, 2) == 0);

        /* Isolate this scenario, then simulate a table member which
         * predates this restore. */
        fake_perm_count = 0;
        fake_temp_count = 0;
        assert(p_add("203.0.113.200") == 0);
        assert(address_manager_init(&reloaded, &ops, 1) == 0);
        fail_temp_add = 1;
        assert(address_manager_restore(&reloaded) == -1);
        fail_temp_add = 0;

        assert(reloaded.permanent_count == 2);
        assert(reloaded.temporary_count == 2);
        assert(fake_perm_count == 3);
        assert(fake_temp_count == 0);
        assert(!strcmp(fake_perm[0], "203.0.113.200"));
        assert(address_manager_restore(&reloaded) == 0);
        assert(fake_perm_count == 3);
        assert(fake_temp_count == 2);
    }

    /* Expiry must restore earlier PF deletions if a later delete fails,
     * and must restore all deleted entries if persistence cannot commit. */
    {
        struct storage_temporary entries[2];
        char moved[512];

        snprintf(entries[0].ip, sizeof(entries[0].ip), "192.0.2.70");
        entries[0].expires_at = now + 10;
        snprintf(entries[1].ip, sizeof(entries[1].ip), "192.0.2.71");
        entries[1].expires_at = now + 20;
        assert(storage_save_temporary(entries, 2) == 0);
        fake_temp_count = 0;
        assert(t_add(entries[0].ip) == 0);
        assert(t_add(entries[1].ip) == 0);
        assert(address_manager_init(&reloaded, &ops, 1) == 0);

        temp_delete_calls = 0;
        fail_temp_delete_on_call = 2;
        assert(address_manager_expire(&reloaded, now + 30, &expired) == -1);
        fail_temp_delete_on_call = 0;
        assert(reloaded.temporary_count == 2);
        assert(fake_temp_count == 2);
        assert(!strcmp(fake_temp[0], entries[0].ip));
        assert(!strcmp(fake_temp[1], entries[1].ip));

        snprintf(moved, sizeof(moved), "%s.expire-rollback", dir);
        assert(rename(dir, moved) == 0);
        assert(address_manager_expire(&reloaded, now + 30, &expired) == -1);
        assert(rename(moved, dir) == 0);
        assert(reloaded.temporary_count == 2);
        assert(fake_temp_count == 2);
        assert(!strcmp(fake_temp[0], entries[0].ip));
        assert(!strcmp(fake_temp[1], entries[1].ip));
    }

    {
        char path[512];
        snprintf(path, sizeof(path), "%s/permanent.list", dir); unlink(path);
        snprintf(path, sizeof(path), "%s/temporary.list", dir); unlink(path);
    }
    assert(rmdir(dir) == 0);
    puts("PASS: address manager add/delete, rollback, reload, restore and expiry");
    return 0;
}
