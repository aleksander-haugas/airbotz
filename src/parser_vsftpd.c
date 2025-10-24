#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "../include/parser_vsftpd.h"
#include "../include/rules.h" // Se necesita para rules_handle_action

#define ALERT_FILE "/var/log/airbotz_alerts.json"

/* ---------- JSON escaping (Sin cambios) ---------- */
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

/* ---------- IP Extraction Utility ---------- */
/*
 * vsftpd logs often contain the IP in the format: "Client "1.2.3.4""
 * or in the final token for TRANSFER logs. This function tries to extract it.
 */
static int extract_vsftpd_ip(const char *line, char *ip_out, size_t ip_size) {
    // 1. Try to find the common "Client "IP"" pattern
    const char *client_ptr = strstr(line, "Client \"");
    if (client_ptr) {
        client_ptr += strlen("Client \"");
        const char *end_quote = strchr(client_ptr, '\"');
        if (end_quote) {
            size_t len = end_quote - client_ptr;
            if (len < ip_size) {
                strncpy(ip_out, client_ptr, len);
                ip_out[len] = '\0';
                return 1;
            }
        }
    }

    // 2. Fallback for transfer logs (assuming IP is the final or near-final token)
    // This is less reliable but necessary if the format varies.
    // We'll skip complex tokenization and rely primarily on the "Client" pattern.
    // For simplicity and safety in production code, we will return 0 if the pattern is not found.
    // If a more complex log format is used (e.g., system logging), this may need adjustment.

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
            "{\"timestamp\":\"%s\",\"service\":\"vsftpd\",\"event\":\"%s\",\"ip\":\"%s\",\"line\":\"%s\"}\n",
            ts, event, ip ? ip : "-", escaped_line);
        fclose(out);
    }
}

void parse_vsftpd_line(const char *line) {
    char ip[64] = {0};
    int ip_found = extract_vsftpd_ip(line, ip, sizeof(ip));
    const char *ip_ptr = ip_found ? ip : NULL;

    // Logins
    if (strstr(line, "OK LOGIN")) {
        if (strstr(line, "ANONYMOUS")) {
            write_alert_enhanced("ftp_anonymous_access", ip_ptr, line);
        } else {
            write_alert_enhanced("ftp_login_success", ip_ptr, line);
        }
        return;
    }

    if (strstr(line, "FAIL LOGIN")) {
        const char *event_name;

        // -------------------------------------------------------------
        // PUNTO CLAVE: LLAMADA A rules_handle_action para Brute Force
        // -------------------------------------------------------------
        if (ip_ptr) {
            // El IP es el dato esencial para el rate-limiting
            rules_handle_action("vsftpd", "ftp_login_failed", ip_ptr, line);
        }

        if (strstr(line, "Username:")) {
            event_name = "ftp_invalid_user";
        } else {
            event_name = "ftp_login_failed";
        }

        write_alert_enhanced(event_name, ip_ptr, line);
        return;
    }

    // Transferencias
    if (strstr(line, "UPLOAD:")) {
        write_alert_enhanced("ftp_upload_detected", ip_ptr, line);
        return;
    }
    if (strstr(line, "DOWNLOAD:")) {
        write_alert_enhanced("ftp_download_detected", ip_ptr, line);
        return;
    }

    // Timeout / desconexiones
    if (strstr(line, "Idle session timeout")) {
        write_alert_enhanced("ftp_idle_timeout", ip_ptr, line);
        return;
    }
    if (strstr(line, "disconnected")) {
        write_alert_enhanced("ftp_client_disconnected", ip_ptr, line);
        return;
    }

    // Comandos sospechosos
    if (strstr(line, "COMMAND not understood")) {
        write_alert_enhanced("ftp_suspicious_command", ip_ptr, line);
        return;
    }
}

