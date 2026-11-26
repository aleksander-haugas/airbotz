#ifndef AIRBOTZ_STORAGE_H
#define AIRBOTZ_STORAGE_H

#include <stddef.h>
#include <time.h>

#define STORAGE_IP_LEN 46
#define STORAGE_MAX_ENTRIES 4096

struct storage_temporary {
    char ip[STORAGE_IP_LEN];
    time_t expires_at;
};

/* Creates/validates a private, owner-only persistence directory. */
int storage_init(const char *directory);

/* Load functions return 0 on success; capacity overflow or malformed data is an error. */
int storage_load_permanent(char ips[][STORAGE_IP_LEN], size_t capacity, size_t *count);
int storage_load_temporary(struct storage_temporary *entries, size_t capacity, size_t *count);

/* Save functions replace the complete corresponding list atomically. */
int storage_save_permanent(const char ips[][STORAGE_IP_LEN], size_t count);
int storage_save_temporary(const struct storage_temporary *entries, size_t count);

#endif
