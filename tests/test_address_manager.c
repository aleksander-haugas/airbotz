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
static int fail_perm_add, fail_temp_delete;

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
static int p_del(const char *ip) { return del_from(fake_perm, &fake_perm_count, ip); }
static int t_add(const char *ip) { return add_to(fake_temp, &fake_temp_count, ip); }
static int t_del(const char *ip) { if (fail_temp_delete) return -1; return del_from(fake_temp, &fake_temp_count, ip); }

int main(void)
{
    char dir[] = "/tmp/airbotz-manager.XXXXXX";
    struct address_manager manager, reloaded;
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

    fail_perm_add = 1;
    assert(address_manager_add_permanent(&manager, "198.51.100.2") == -1);
    fail_perm_add = 0;
    assert(manager.permanent_count == 1);

    fail_temp_delete = 1;
    assert(address_manager_delete_temporary(&manager, "2001:db8::10") == -1);
    fail_temp_delete = 0;
    assert(manager.temporary_count == 1);

    assert(address_manager_expire(&manager, now + 121, &expired) == 0);
    assert(expired == 1 && manager.temporary_count == 0 && fake_temp_count == 0);
    assert(address_manager_delete_permanent(&manager, "192.0.2.10") == 0);
    assert(manager.permanent_count == 0 && fake_perm_count == 0);

    {
        char path[512];
        snprintf(path, sizeof(path), "%s/permanent.list", dir); unlink(path);
        snprintf(path, sizeof(path), "%s/temporary.list", dir); unlink(path);
    }
    assert(rmdir(dir) == 0);
    puts("PASS: address manager add/delete, rollback, reload, restore and expiry");
    return 0;
}
