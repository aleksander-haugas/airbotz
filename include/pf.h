#ifndef AIRBOTZ_PF_H
#define AIRBOTZ_PF_H

#include <stddef.h>

#define PF_IP_LEN 46
#define PF_SNAPSHOT_MAX_ENTRIES 4096
#define PF_SNAPSHOT_MAX_BYTES 262144

int pf_init(const char *temp_table, const char *perm_table);
int pf_status(void);
int pf_get_status(int *enabled);
int pf_parse_status_output(const char *output, size_t length, int *enabled);
int pf_temp_add(const char *ip);
int pf_temp_delete(const char *ip);
int pf_perm_add(const char *ip);
int pf_perm_delete(const char *ip);
int pf_temp_snapshot(char entries[][PF_IP_LEN], size_t capacity,
                     size_t *count);
int pf_perm_snapshot(char entries[][PF_IP_LEN], size_t capacity,
                     size_t *count);
/* Strict parser shared by the command wrapper and deterministic unit tests.
 * Input must contain complete newline-terminated address records. */
int pf_parse_table_output(const char *output, size_t length,
                          char entries[][PF_IP_LEN], size_t capacity,
                          size_t *count);
void pf_shutdown(void);
int pf_valid_address(const char *ip);

#ifdef AIRBOTZ_PF_TESTING
void pf_test_set_command_path(const char *path);
#endif

#endif
