#ifndef AIRBOTZ_PF_H
#define AIRBOTZ_PF_H
int pf_init(const char *temp_table, const char *perm_table);
int pf_status(void);
int pf_temp_add(const char *ip);
int pf_temp_delete(const char *ip);
int pf_perm_add(const char *ip);
int pf_perm_delete(const char *ip);
void pf_shutdown(void);
int pf_valid_address(const char *ip);
#endif
