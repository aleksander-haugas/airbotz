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

/* Save functions replace the complete corresponding list atomically.
 * Return 0 when the file and directory entry are durable; -1 if the
 * destination was not replaced; -2 if rename succeeded but directory
 * fsync/close failed, so the replacement is visible but durability is
 * uncertain. Callers must treat -2 as committed-but-uncertain, not rollback. */
int storage_save_permanent(const char ips[][STORAGE_IP_LEN], size_t count);
int storage_save_temporary(const struct storage_temporary *entries, size_t count);

#ifdef AIRBOTZ_STORAGE_TESTING
/* Test-only deterministic fault injection; not present in production builds. */
enum storage_test_failure {
    STORAGE_TEST_FAIL_NONE = 0,
    STORAGE_TEST_FAIL_WRITE,
    STORAGE_TEST_FAIL_FLUSH,
    STORAGE_TEST_FAIL_FILE_FSYNC,
    STORAGE_TEST_FAIL_FILE_CLOSE,
    STORAGE_TEST_FAIL_RENAME,
    STORAGE_TEST_FAIL_DIRECTORY_FSYNC,
    STORAGE_TEST_FAIL_DIRECTORY_CLOSE
};
void storage_test_fail_stage(int stage);
#endif

#endif
