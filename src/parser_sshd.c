#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "../include/parser_sshd.h"
#include "../include/rules.h" // Se necesita para rules_handle_action

#define ALERT_FILE "/var/log/airbotz_alerts.json"

/* ---------- JSON escaping (Copia de vsftpd.c) ---------- */
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

/* ---------- IP Extraction Utility for SSHD ---------- */
static int extract_sshd_ip(const char *line, char *ip_out, size_t ip_size) {
    // Buscar el patrón " from IP_ADDRESS port" o " for USER from IP_ADDRESS port"
    // El formato varía, pero el IP siempre está precedido por 'from ' y seguido de ' port' o un espacio/fin de línea.

    const char *from_ptr = strstr(line, "from ");
    if (!from_ptr) {
        ip_out[0] = '\0';
        return 0;
    }

    from_ptr += strlen("from ");
    const char *space_ptr = strchr(from_ptr, ' ');
    const char *port_ptr = strstr(from_ptr, " port");
    const char *end_ptr = NULL;

    if (port_ptr && (!space_ptr || port_ptr < space_ptr)) {
        end_ptr = port_ptr;
    } else if (space_ptr) {
        end_ptr = space_ptr;
    }
    
    // Fallback: si no encuentra nada, asumimos que es el final del log si no hay más texto.
    if (!end_ptr) {
        end_ptr = line + strlen(line);
    }
    
    size_t len = end_ptr - from_ptr;
    if (len > 0 && len < ip_size) {
        strncpy(ip_out, from_ptr, len);
        ip_out[len] = '\0';
        // Validación básica de IP (opcional, pero útil)
        if (strchr(ip_out, '.') || strchr(ip_out, ':')) {
             return 1;
        }
    }

    ip_out[0] = '\0';
    return 0;
}

/* ---------- write_alert_enhanced (Ahora incluye IP) ---------- */
static inline void write_alert_enhanced(const char *event, const char *ip, const char *line) {
    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));

    char escaped_line[8192];
    json_escape(line, escaped_line, sizeof(escaped_line));

    FILE *out = fopen(ALERT_FILE, "a");
    if (out) {
        // Incluimos el campo 'ip' en el JSON. Usamos "-" si no se pudo extraer.
        fprintf(out,
            "{\"timestamp\":\"%s\",\"service\":\"sshd\",\"event\":\"%s\",\"ip\":\"%s\",\"line\":\"%s\"}\n",
            ts, event, ip ? ip : "-", escaped_line);
        fclose(out);
    }
}

void parse_sshd_line(const char *line) {
    char ip[64] = {0};
    int ip_found = extract_sshd_ip(line, ip, sizeof(ip));
    const char *ip_ptr = ip_found ? ip : NULL;

    // Conexiones fallidas / Invalid user
    if (strstr(line, "Failed password") || strstr(line, "Invalid user")) {
        const char *event_name = strstr(line, "Invalid user") ? "sshd_invalid_user" : "sshd_auth_failed";

        // -------------------------------------------------------------
        // PUNTO CLAVE: LLAMADA A rules_handle_action para Brute Force SSH
        // -------------------------------------------------------------
        if (ip_ptr) {
            // El IP es el dato esencial para el rate-limiting
            rules_handle_action("sshd", event_name, ip_ptr, line);
        }
        write_alert_enhanced(event_name, ip_ptr, line);
        return;
    }

    // Login exitoso
    if (strstr(line, "Accepted password") || strstr(line, "Accepted publickey")) {
        write_alert_enhanced("sshd_login_success", ip_ptr, line);
        return;
    }

    // Posibles ataques de diccionario (ej: SSHD a menudo loguea mensajes específicos)
    if (strstr(line, "Connection closed by authenticating user")) {
        // Esto a veces puede ser una señal de ataques muy rápidos.
        // Podríamos considerar el rate-limiting aquí también si fuera muy ruidoso,
        // pero por ahora solo alertamos.
        write_alert_enhanced("sshd_connection_closed_auth", ip_ptr, line);
        return;
    }
    
    // Intentos de inyección/ataques en la fase de conexión.
    if (strstr(line, "Did not receive identification string")) {
        write_alert_enhanced("sshd_protocol_violation", ip_ptr, line);
        return;
    }
}

