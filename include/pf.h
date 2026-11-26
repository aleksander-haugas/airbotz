#ifndef AIRBOTZ_PF_H
#define AIRBOTZ_PF_H
int pf_init(const char *table);
int pf_status(void);
int pf_table_add(const char *ip);
int pf_table_delete(const char *ip);
void pf_shutdown(void);
int pf_valid_address(const char *ip);
#endif
