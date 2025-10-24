#ifndef RULES_H
#define RULES_H

#include <time.h>   // para time_t

#define MAX_COUNTERS 8192
#define MAX_BAN_ENTRIES 4096

int rules_init(const char *primary_conf, const char *fallback_conf);
void rules_shutdown(void);
void rules_unban_expired(void);
void rules_cleanup_expired_bans(void);

// ----------------- tipos usados en status -----------------
typedef struct {
    char ip[64];
    char rule_id[128];  // ej: "nginx/sensitive_path_access"
    long count;
    time_t first_hit_ts;
} Counter;

typedef struct {
    char ip[64];
    char rule_id[128]; // opcional para identificar la regla
    time_t ban_expire; // 0 = permanente
} ActiveBan;

// getters para status
int rules_get_active_bans_count(void);
void rules_get_active_bans(ActiveBan **bans, int *count);

int rules_get_counters_count(void);
void rules_get_counters(Counter **cnts, int *count);

// La función clave para enviar eventos al motor central de reglas
void rules_handle_action(const char *service, const char *event_type, const char *ip_address, const char *raw_log);

#endif

