#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "../include/parser_nginx.h"
#include "../include/rules.h" // NECESARIO para rules_handle_action

#define ALERT_FILE "/var/log/airbotz_alerts.json"

/* Todas las definiciones de rate-limiting internas (BRUTE_WINDOW, HASH_SIZE, etc.)
 * han sido eliminadas. Ahora dependen de la configuracin en rules.conf.
 */

#define MAX_URI_SAMPLE 256
#define MAX_UASAMPLE 256

/* ---------- JSON escaping ---------- */
static void json_escape(const char *input, char *output, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j + 1 < out_size; i++) {
        if (input[i] == '\"' || input[i] == '\\') {
            if (j + 2 >= out_size) break;
            output[j++] = '\\';
            output[j++] = input[i];
        } else if (input[i] == '\n') {
            if (j + 2 >= out_size) break;
            output[j++] = '\\';
            output[j++] = 'n';
        } else if (input[i] == '\r') {
            if (j + 2 >= out_size) break;
            output[j++] = '\\';
            output[j++] = 'r';
        } else {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

/* ---------- write_alert_enriched (Simplificado para monitoreo externo) ---------- */
// Escribe un log JSON enriquecido. Se llama por el parser para enviar informacin
// a un monitor externo/UI, mientras que rules_handle_action gestiona la accin.
static inline void write_alert_enriched(const char *event, const char *ip,
                                        const char *method, const char *uri,
                                        int status, const char *ua) {
    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));

    char escaped_uri[1024];
    char escaped_ua[MAX_UASAMPLE];
    json_escape(uri ? uri : "", escaped_uri, sizeof(escaped_uri));
    json_escape(ua ? ua : "", escaped_ua, sizeof(escaped_ua));

    FILE *out = fopen(ALERT_FILE, "a");
    if (!out) return;

    // Estructura JSON simple (sin conteo, ya que rules.c lo gestiona)
    fprintf(out,
        "{\"timestamp\":\"%s\",\"service\":\"nginx\",\"event\":\"%s\",\"ip\":\"%s\",\"method\":\"%s\",\"uri\":\"%s\",\"status\":%d,\"ua\":\"%s\"}\n",
        ts, event, ip ? ip : "-", method ? method : "-", escaped_uri, status, escaped_ua);
    
    fclose(out);
}


/* ---------- Utilidades para parseo ---------- */

/* extrae primer token separado por espacios */
static void first_token(const char *s, char *out, size_t outsz) {
    size_t i = 0;
    while (*s && isspace((unsigned char)*s)) s++;
    while (*s && !isspace((unsigned char)*s) && i + 1 < outsz) {
        out[i++] = *s++;
    }
    out[i] = '\0';
}

/* busca "METHOD URI" en la parte de request: "GET /path HTTP/1.1" */
static void extract_request(const char *s, char *method, size_t msz, char *uri, size_t usz) {
    const char *p = strchr(s, '\"');
    if (!p) { method[0]=0; uri[0]=0; return; }
    p++; /* skip " */
    size_t i=0;
    while (*p && !isspace((unsigned char)*p) && i+1<msz) method[i++]=*p++;
    method[i]=0;
    while (*p && isspace((unsigned char)*p)) p++;
    i=0;
    while (*p && !isspace((unsigned char)*p) && i+1<usz) uri[i++]=*p++;
    uri[i]=0;
}

/* obtiene status code (nmero despus de request) */
static int extract_status(const char *s) {
    const char *p = strrchr(s, '\"');
    if (!p) return -1;
    p++;
    while (*p && isspace((unsigned char)*p)) p++;
    int st = -1;
    if (*p) st = atoi(p);
    return st;
}

/* extrae user-agent: last quoted string usually */
static void extract_ua(const char *s, char *ua, size_t usz) {
    const char *p = s;
    const char *lastq = NULL;
    while ((p = strchr(p, '\"')) != NULL) {
        lastq = p;
        p++;
    }
    if (!lastq) { ua[0]=0; return; }
    int inq = 0;
    const char *start = NULL, *end = NULL;
    p = s;
    while (*p) {
        if (*p == '\"') {
            if (!inq) {
                start = p+1;
                inq = 1;
            } else {
                end = p;
                inq = 0;
            }
        }
        p++;
    }
    if (start && end && end > start) {
        size_t len = end - start;
        if (len >= usz) len = usz - 1;
        memcpy(ua, start, len);
        ua[len] = '\0';
    } else {
        ua[0] = '\0';
    }
}

/* --- Los structs y funciones de contadores internos (ip_entry, hash_table, etc.) han sido eliminados --- */

/* ---------- detection helpers (pattern checks) ---------- */

static int is_login_endpoint(const char *uri) {
    if (!uri) return 0;
    const char *login_paths[] = {
        "/wp-login.php", "/xmlrpc.php", "/phpmyadmin", "/login", "/user/login", "/administrator/index.php", "/admin", NULL
    };
    for (int i=0; login_paths[i]; i++) {
        if (strcasestr(uri, login_paths[i])) return 1;
    }
    return 0;
}

static int contains_sqli_pattern(const char *s) {
    if (!s) return 0;
    const char *patterns[] = {
        "union select", "select ", " or ", " and ", "sleep(", "benchmark(", "load_file(", "information_schema", "concat(", "group_concat(", "-- ", "' or '1'='1", NULL
    };
    for (int i=0; patterns[i]; i++) {
        if (strcasestr(s, patterns[i])) return 1;
    }
    if (strcasestr(s, "%27") && (strcasestr(s, "union") || strcasestr(s, "select"))) return 1;
    return 0;
}

static int contains_xss_pattern(const char *s) {
    if (!s) return 0;
    if (strcasestr(s, "<script")) return 1;
    if (strcasestr(s, "javascript:")) return 1;
    if (strcasestr(s, "%3Cscript")) return 1;
    if (strcasestr(s, "onerror=") || strcasestr(s, "onload=")) return 1;
    if (strcasestr(s, "<img") && strcasestr(s, "onerror")) return 1;
    return 0;
}

/* ===================== Listas para paths sensibles / patterns ===================== */

static const char *sensitive_files[] = {
    "/.env", "/.htaccess", "/.htpasswd", "/phpinfo.php", "/config.php",
    "/wp-config.php", "/database.yml", "/settings.py", "/localsettings.py",
    "/.git/config", "/.gitignore", "/.svn/entries", "/backup.zip",
    "/db_backup.sql", "/composer.json", "/composer.lock", "/package.json",
    "/yarn.lock", "/Gemfile", "/Cargo.toml", "/Makefile", "/.bash_history",
    "/.ssh/id_rsa", "/id_rsa", "/private.key", "/server.key", "/ssl.key",
    "/.DS_Store", "/Thumbs.db",
    NULL
};

static const char *admin_dirs[] = {
    "/administrator", "/administrator/", "/wp-admin",
    "/wp-admin/", "/wp-login.php", "/cpanel",
    "/phpmyadmin", "/pma", "/dbadmin", "/webadmin", "/server-status",
    "/controlpanel", "/cms", 
    NULL
};

static const char *known_vuln_endpoints[] = {
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
    "/wp-content/plugins/revslider/admin",
    "/boaform/admin/formLogin",
    "/solr/admin/info/system",
    "/HNAP1",
    "/hudson",
    "/jmx-console",
    "/manager/html",
    "/actuator/env",
    "/actuator/heapdump",
    "/graphql",
    NULL
};

static const char *backup_extensions[] = {
    ".bak", ".backup", ".old", ".tar", ".tar.gz", ".zip", ".7z",
    ".rar", ".swp", ".save", ".orig", ".tmp", ".sql",
    NULL
};

/* helper: match any substring list */
static int matches_list(const char *uri, const char *const list[]) {
    if (!uri) return 0;
    for (int i = 0; list[i] != NULL; i++) {
        if (strcasestr(uri, list[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

/* helper: check extension suffixes */
static int has_extension(const char *uri, const char *const list[]) {
    if (!uri) return 0;
    size_t len = strlen(uri);
    for (int i = 0; list[i] != NULL; i++) {
        size_t ext_len = strlen(list[i]);
        if (len >= ext_len && strcasecmp(uri + len - ext_len, list[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* --- La lgica de ScanEntry y ScanEntry ha sido eliminada --- */

/* ---------- main parser (exposed) ---------- */

/* parse lines like: <ip> - - [time] "METHOD URI HTTP/1.1" status size "ref" "ua" */
void parse_nginx_line(const char *line) {
    if (!line || !line[0]) return;

    char ip[64] = {0};
    first_token(line, ip, sizeof(ip));
    if (!ip[0]) return;

    char method[16] = {0};
    char uri[1024] = {0};
    extract_request(line, method, sizeof(method), uri, sizeof(uri));
    int status = extract_status(line);

    char ua[MAX_UASAMPLE] = {0};
    extract_ua(line, ua, sizeof(ua));


    /*
     * REGLA 0: Hit a un path sensible / conocido de ataque
     * Evento: sensitive_path_hit
     */
    if (matches_list(uri, sensitive_files) ||
        matches_list(uri, admin_dirs) ||
        matches_list(uri, known_vuln_endpoints) ||
        has_extension(uri, backup_extensions)) {
        
        // Reportar el evento, rules.c gestiona el conteo y la accin
        rules_handle_action("nginx", "sensitive_path_hit", ip, line);
        write_alert_enriched("sensitive_path_hit", ip, method, uri, status, ua);
    }


    /*
     * REGLA 1: Fuerza bruta (login_attempt)
     * Evento: login_attempt
     */
    if (strcasecmp(method, "POST") == 0 && is_login_endpoint(uri)) {
        // Reportar el evento, rules.c gestiona el conteo y la accin
        rules_handle_action("nginx", "login_attempt", ip, line);
        write_alert_enriched("login_attempt", ip, method, uri, status, ua);
    }

    /*
     * REGLA 2: SQLi detection
     * Evento: sql_injection_attempt
     */
    if (contains_sqli_pattern(uri) || contains_sqli_pattern(ua)) {
        // Reportar el evento, rules.c gestiona el conteo y la accin
        rules_handle_action("nginx", "sql_injection_attempt", ip, line);
        write_alert_enriched("sql_injection_attempt", ip, method, uri, status, ua);
    }

    /*
     * REGLA 3: XSS detection
     * Evento: xss_attempt
     */
    if (contains_xss_pattern(uri) || contains_xss_pattern(ua)) {
        // Reportar el evento, rules.c gestiona el conteo y la accin
        rules_handle_action("nginx", "xss_attempt", ip, line);
        write_alert_enriched("xss_attempt", ip, method, uri, status, ua);
    }


    /*
     * REGLA 4: Fuzzing / High 404 Rate
     * Evento: 404_hit
     */
    if (status == 404) {
        // Reportar el evento, rules.c gestiona el conteo y la accin
        rules_handle_action("nginx", "404_hit", ip, line);
        write_alert_enriched("404_hit", ip, method, uri, status, ua);
    } 
    
    /*
     * REGLA 5: High 4xx Rate (otros cdigos 4xx)
     * Evento: 4xx_hit
     */
    else if (status >= 400 && status < 500) {
        // Reportar el evento, rules.c gestiona el conteo y la accin
        rules_handle_action("nginx", "4xx_hit", ip, line);
        write_alert_enriched("4xx_hit", ip, method, uri, status, ua);
    }
}
