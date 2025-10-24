#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <arpa/inet.h>

#include "../include/rules.h"
#include "../include/state_manager.h"

#define MAX_BAN_ENTRIES 4096
#define MAX_COUNTERS    8192

typedef enum { ACTION_BAN_TEMP, ACTION_BAN_PERM, ACTION_ALERT_ONLY, ACTION_LOG_ONLY, ACTION_WATCHLIST } ActionType;

typedef struct {
    char service[32];
    char event[64];
    int threshold;
    int window;      // segundos
    ActionType action;
    int duration;    // solo para ban_temp
} Rule;

// tablas de PF
const char *ban_temp_table = "airbotz_temp";
const char *ban_perm_table = "airbotz_perm";

// arrays internos
static Rule rules[MAX_BAN_ENTRIES];
static int rule_count = 0;

static ActiveBan active_bans[MAX_BAN_ENTRIES];
static int active_ban_count = 0;

/* --------------------- Utilidades -------------------- */

// Funcin de utilidad para convertir IP de string a uint32_t (network byte order)
static uint32_t ip_to_u32(const char *ip_str) {
    // inet_addr() devuelve -1 o INADDR_NONE en caso de error
    return (uint32_t)inet_addr(ip_str);
}

// --------------------- Logging -----------------------
static void log_rules(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    FILE *f = fopen("/var/log/airbotz.log", "a");
    if(f) {
        vfprintf(f, fmt, ap);
        fprintf(f, "\n");
        fclose(f);
    }
    va_end(ap);
}

// --------------------- Active bans -----------------
static ActiveBan *active_ban_find(const char *ip, const char *rule_id) {
    for(int i=0;i<active_ban_count;i++)
        if(strcmp(active_bans[i].ip, ip)==0 && strcmp(active_bans[i].rule_id, rule_id)==0)
            return &active_bans[i];
    return NULL;
}

// NUEVA FUNCIN: Verifica si la IP tiene un baneo permanente activo (expire == 0)
static int is_ip_permanently_banned(const char *ip_str) {
    for(int i = 0; i < active_ban_count; i++) {
        // Un baneo es permanente si su tiempo de expiracin es 0
        if(strcmp(active_bans[i].ip, ip_str) == 0 && active_bans[i].ban_expire == 0) {
            return 1; // IP tiene baneo permanente
        }
    }
    return 0;
}

static ActiveBan *active_ban_add(const char *ip, const char *rule_id, time_t expire) {
    ActiveBan *existing = active_ban_find(ip, rule_id);
    if(existing) {
        // Solo actualizamos la expiracin si no es un baneo permanente.
        // Un baneo permanente (expire=0) no se actualiza a un temporal.
        if (existing->ban_expire != 0) {
            existing->ban_expire = expire; // actualizar expiracin
        }
        return existing;
    }
    if(active_ban_count >= MAX_BAN_ENTRIES) return NULL;
    ActiveBan *b = &active_bans[active_ban_count++];
    strncpy(b->ip, ip, sizeof(b->ip)-1);
    strncpy(b->rule_id, rule_id, sizeof(b->rule_id)-1);
    b->ban_expire = expire;
    return b;
}

static void active_ban_remove(int index) {
    if(index<0 || index>=active_ban_count) return;
    if(index != active_ban_count-1)
        active_bans[index] = active_bans[active_ban_count-1];
    active_ban_count--;
}

// getters para status
int rules_get_active_bans_count(void) {
    return active_ban_count;
}

void rules_get_active_bans(ActiveBan **bans, int *count) {
    if (bans) *bans = active_bans;
    if (count) *count = active_ban_count;
}


// --------------------- PF control ------------------
static void pfctl_add(const char *table, const char *ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/sbin/pfctl -t %s -T add %s", table, ip);
    // Aadimos '> /dev/null 2>&1' para evitar que 'pfctl' imprima mensajes si la IP ya existe
    // y solo dependemos de nuestro log.
    strncat(cmd, " > /dev/null 2>&1", sizeof(cmd) - strlen(cmd) - 1);
    system(cmd);
    log_rules("[rules] pfctl add %s %s", table, ip);
}

static void pfctl_delete(const char *table, const char *ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/sbin/pfctl -t %s -T delete %s", table, ip);
    strncat(cmd, " > /dev/null 2>&1", sizeof(cmd) - strlen(cmd) - 1);
    system(cmd);
    log_rules("[rules] pfctl delete %s %s", table, ip);
}

// --------------------- Sync PF al iniciar -----------
static void sync_pf_table(const char *table, int permanent) {
    char line[128];
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/sbin/pfctl -t %s -T show", table);
    FILE *f = popen(cmd, "r");
    if(!f) return;

    while(fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0; // quitar \n
        if(strlen(line)==0) continue;
        // Al sincronizar desde PF, usamos el nombre de la tabla como rule_id
        active_ban_add(line, permanent ? ban_perm_table : ban_temp_table, permanent ? 0 : time(NULL)+3600);
    }
    pclose(f);
}

// --------------------- Carga reglas ----------------
static ActionType parse_action(const char *action) {
    if(strcmp(action,"ban_temp")==0) return ACTION_BAN_TEMP;
    if(strcmp(action,"ban_perm")==0) return ACTION_BAN_PERM;
    if(strcmp(action,"alert_only")==0) return ACTION_ALERT_ONLY;
    if(strcmp(action,"log_only")==0) return ACTION_LOG_ONLY;
    if(strcmp(action,"watchlist")==0) return ACTION_WATCHLIST;
    return ACTION_LOG_ONLY;
}

static void load_rules(const char *conf) {
    FILE *f = fopen(conf,"r");
    if(!f) {
        log_rules("[rules] no se pudo abrir config: %s", conf);
        return;
    }

    char line[512];
    while(fgets(line,sizeof(line),f)) {
        if(line[0]=='#' || strlen(line)<5) continue;
        char service[32], event[64], action_str[32];
        int threshold, window, duration;
        if(sscanf(line,"%31s %63s %d %d %31s %d",
            service,event,&threshold,&window,action_str,&duration)!=6) continue;
        Rule *r = &rules[rule_count++];
        strncpy(r->service, service, sizeof(r->service)-1);
        strncpy(r->event, event, sizeof(r->event)-1);
        r->threshold = threshold;
        r->window = window;
        r->action = parse_action(action_str);
        r->duration = duration;
    }
    fclose(f);
    log_rules("[rules] %d reglas cargadas (%s)", rule_count, conf);
}

/* --------------------- Lookup de Reglas ------------------ */

Rule *rules_find_rule(const char *service, const char *event) {
    for(int i = 0; i < rule_count; i++) {
        if(strcmp(rules[i].service, service) == 0 && strcmp(rules[i].event, event) == 0) {
            return &rules[i];
        }
    }
    return NULL;
}

// -------------------- Counter Inteligente --------------------
static int rules_check_and_update_counter(const Rule *rule, const char *service, const char *event, const char *ip_str) {
    uint32_t ip_bin = ip_to_u32(ip_str);
    AttackCounter *counter = state_manager_get_counter(ip_bin, service, event);
    if (!counter) return 0;

    time_t now = time(NULL);

    // Inicialización del primer intento
    if (counter->first_attempt_ts == 0) {
        counter->first_attempt_ts = now;
        counter->last_attempt_ts  = now;
        counter->failure_count    = 1;
        counter->escalation_level = 0;
        return 0;
    }

    // Reset completo si pasó mucho tiempo sin actividad (2 ventanas)
    if (difftime(now, counter->last_attempt_ts) > (rule->window * 2)) {
        counter->failure_count    = 1;
        counter->first_attempt_ts = now;
        counter->escalation_level = 0;
        counter->last_attempt_ts  = now;
        return 0;
    }

    // Reset parcial si la ventana se agotó
    if (difftime(now, counter->first_attempt_ts) > rule->window) {
        counter->failure_count    = 1;
        counter->first_attempt_ts = now;
    } else {
        counter->failure_count++;
    }

    counter->last_attempt_ts = now;

    // Cuando supera el umbral, reiniciamos el contador y aumentamos el nivel de reincidencia
    if (counter->failure_count >= (unsigned int)rule->threshold) {
        counter->failure_count = 0;
        counter->first_attempt_ts = now;
        counter->escalation_level++;
        return counter->escalation_level; // devuelve cuántas veces alcanzó el umbral
    }

    return 0;
}


/* --------------------- Manejo de Acciones (rules_handle_action - Centralizado) ------------------ */
void rules_handle_action(const char *service, const char *event, const char *ip_str, const char *line) {
    Rule *rule = rules_find_rule(service, event);
    if (!rule) return; // No hay regla para este evento/servicio, ignorar

    /* --- 0. Intentar actualizar/consultar el contador inteligente --- */
    int escalation = 0;
    if (rule->window > 0) {
        escalation = rules_check_and_update_counter(rule, service, event, ip_str);
        if (escalation == 0) {
            // No alcanzó umbral aún -> nada que hacer
            return;
        }
        // escalation >= 1 significa que acabó de alcanzar el umbral (1 = primera vez, 2+ = reincidencia)
    }

    /* --- 1. Preparar estado / comprobar bans existentes --- */
    ActiveBan *b = active_ban_find(ip_str, rule->event);
    int perm_banned = is_ip_permanently_banned(ip_str);
    time_t now = time(NULL);

    /* --- 2. Si la IP ha alcanzado el umbral varias veces -> promover a permanente --- */
    if (escalation >= 2) {
        // Si ya es permamente baneada por cualquier regla, solo logueamos re-trigger.
        if (perm_banned) {
            log_rules("[rules] ESCALATION re-trigger perm ban %s for %s/%s. Log line: %s", ip_str, service, event, line);
            return;
        }

        // Registrar/actualizar entrada de baneo permanente asociada a esta regla
        if (!b) {
            b = active_ban_add(ip_str, rule->event, 0); // expire = 0 => perm
        } else {
            // si existía baneo temporal para esta regla, lo marcamos permanente
            b->ban_expire = 0;
        }

        // Añadimos a tabla perm y borramos de la temporal por si estaba ahí
        pfctl_add(ban_perm_table, ip_str);
        pfctl_delete(ban_temp_table, ip_str);

        log_rules("[rules] ESCALATION -> ACTION ban_perm %s for %s/%s (escalation=%d). Log line: %s",
                  ip_str, service, event, escalation, line);
        return;
    }

    /* --- 3. Si no hubo escalado a perm, aplicar la acción definida por la regla --- */
    if (rule->action == ACTION_BAN_TEMP) {
        if (perm_banned) {
            // Ya tiene baneo permanente por otra regla: saltamos el ban temporal.
            log_rules("[rules] SKIP ban_temp %s for %s/%s. Already permanently banned.", ip_str, service, event);
            return;
        }

        time_t expire_ts = now + rule->duration;
        if (!b) {
            b = active_ban_add(ip_str, rule->event, expire_ts);
        } else {
            // si ya existe y no es permanente, actualizamos expiración
            if (b->ban_expire != 0) b->ban_expire = expire_ts;
        }

        pfctl_add(ban_temp_table, ip_str);
        log_rules("[rules] ACTION ban_temp %s duration=%d for %s/%s. Log line: %s",
                  ip_str, rule->duration, service, event, line);

    } else if (rule->action == ACTION_BAN_PERM) {
        if (!b) b = active_ban_add(ip_str, rule->event, 0);

        if (perm_banned) {
            log_rules("[rules] RE-TRIGGER ban_perm %s for %s/%s. PF add skipped (already perm banned). Log line: %s",
                      ip_str, service, event, line);
        } else {
            // Nuevo baneo permanente: añadir a tabla perm y limpiar temp
            pfctl_add(ban_perm_table, ip_str);
            pfctl_delete(ban_temp_table, ip_str);
            log_rules("[rules] ACTION ban_perm %s for %s/%s. Log line: %s", ip_str, service, event, line);
        }

    } else if (rule->action == ACTION_ALERT_ONLY) {
        log_rules("[rules] ALERT_ONLY %s/%s ip=%s. Log line: %s", service, event, ip_str, line);

    } else if (rule->action == ACTION_LOG_ONLY) {
        log_rules("[rules] LOG_ONLY %s/%s ip=%s. Log line: %s", service, event, ip_str, line);

    } else if (rule->action == ACTION_WATCHLIST) {
        log_rules("[rules] WATCHLIST %s/%s ip=%s. Log line: %s", service, event, ip_str, line);
    }
}

// --------------------- Limpieza bans temporales -----------
void rules_cleanup_expired_bans(void) {
    time_t now = time(NULL);
    for(int i=active_ban_count-1;i>=0;i--) {
        // Solo verificamos baneo temporal (expire > 0)
        if(active_bans[i].ban_expire>0 && active_bans[i].ban_expire<=now) {
            // Antes de remover, verificamos si existe *otro* baneo permanente para esta IP.
            // Si existe, no borramos la IP de PF, ya que la otra regla lo mantiene.
            // PERO: Como la remocin de PF es idempotente (borrar una IP no existente es inofensivo)
            // y la IP SLO est en la tabla TEMP si NO est en la tabla PERM (debido a la lgica de promocin),
            // el cdigo original es simple y correcto: si el baneo temporal de esta regla expira,
            // intentamos borrar de la tabla temporal.

            // Lgica simple: Si una entrada temporal expira, la borramos del estado interno y de PF.
            pfctl_delete(ban_temp_table, active_bans[i].ip);
            active_ban_remove(i);
        }
    }
}

// --------------------- API pblicas ------------------
int rules_init(const char *primary_conf, const char *fallback_conf) {
    load_rules(primary_conf);
    if(rule_count==0 && fallback_conf) load_rules(fallback_conf);

    sync_pf_table(ban_temp_table, 0);
    sync_pf_table(ban_perm_table, 1);

    rules_cleanup_expired_bans();
    return 0;
}

void rules_shutdown(void) {
    for(int i=0;i<active_ban_count;i++) {
        if(active_bans[i].ban_expire>0) pfctl_delete(ban_temp_table, active_bans[i].ip);
    }
    active_ban_count=0;
    rule_count=0;
    log_rules("[rules] shutdown");
}

