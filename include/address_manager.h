#ifndef AIRBOTZ_ADDRESS_MANAGER_H
#define AIRBOTZ_ADDRESS_MANAGER_H

#include "storage.h"

struct address_manager_ops {
    int (*temp_add)(const char *ip);
    int (*temp_delete)(const char *ip);
    int (*perm_add)(const char *ip);
    int (*perm_delete)(const char *ip);
};

struct address_manager {
    struct address_manager_ops ops;
    int pf_enabled;
    char permanent[STORAGE_MAX_ENTRIES][STORAGE_IP_LEN];
    size_t permanent_count;
    struct storage_temporary temporary[STORAGE_MAX_ENTRIES];
    size_t temporary_count;
};

/* storage_init() must have succeeded before this call.
 * Operations return 0 on durable success, -1 on pre-commit failure (PF
 * rollback attempted), -2 if a PF rollback also fails, and -3 if the
 * storage replacement committed but directory durability is uncertain.
 * On -3, in-memory state follows the visible replacement and PF is not rolled
 * back; callers must report the uncertain durability to the operator. */
int address_manager_init(struct address_manager *manager,
                         const struct address_manager_ops *ops,
                         int pf_enabled);
int address_manager_restore(struct address_manager *manager);
int address_manager_add_permanent(struct address_manager *manager, const char *ip);
int address_manager_delete_permanent(struct address_manager *manager, const char *ip);
int address_manager_add_temporary(struct address_manager *manager, const char *ip,
                                  time_t expires_at);
int address_manager_delete_temporary(struct address_manager *manager, const char *ip);
int address_manager_expire(struct address_manager *manager, time_t now,
                           size_t *expired_count);

#endif
