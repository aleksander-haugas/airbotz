/*
 actions.c - menú interactivo para usar Ollama (TinyLlama) sin curl.
 - Comunicación HTTP POST por sockets.
 - Opciones: Analizar, Banear, Desbanear, Reentrenar (simulado).
 - Lee últimos N eventos desde ALERT_FILE para enviar al modelo.
*/

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define ALERT_FILE "/var/log/airbotz_alerts.json"
#define MAX_INPUT 512
#define DEFAULT_OLLAMA_ADDR "172.16.1.8:11434" /* usa 172.16.1.8 según tu jls */
#define HTTP_BUFSIZE  (1024*16)

static const char *get_ollama_addr(void) {
    const char *env = getenv("OLLAMA_ADDR");
    if (env && env[0]) return env;
    return DEFAULT_OLLAMA_ADDR;
}

/* Split host:port into host and port strings (returned pointers are to buffers we allocate) */
static int split_hostport(const char *addr, char **host_out, char **port_out) {
    char *p = strchr(addr, ':');
    if (!p) return -1;
    size_t hlen = p - addr;
    *host_out = malloc(hlen + 1);
    if (!*host_out) return -1;
    memcpy(*host_out, addr, hlen);
    (*host_out)[hlen] = '\0';
    *port_out = strdup(p + 1);
    if (!*port_out) { free(*host_out); return -1; }
    return 0;
}

/* Minimal IP validator (IPv4 dotted) */
static int is_valid_ipv4(const char *s) {
    int dots = 0;
    const char *p = s;
    while (*p) {
        if (*p == '.') dots++;
        else if (!isdigit((unsigned char)*p)) return 0;
        p++;
    }
    if (dots != 3) return 0;
    /* basic numeric checks */
    int a,b,c,d;
    if (sscanf(s, "%d.%d.%d.%d", &a,&b,&c,&d) != 4) return 0;
    if (a<0||a>255||b<0||b>255||c<0||c>255||d<0||d>255) return 0;
    return 1;
}

/* Very small HTTP POST implementation using blocking sockets.
   Returns 0 on success, -1 on error. response is printed to stdout (or to resp_buf if provided).
*/
static int http_post(const char *host, const char *port, const char *path, const char *content_type,
                     const char *body, char **resp_out, size_t *resp_len_out)
{
    int rv = -1;
    struct addrinfo hints = {0}, *ai = NULL, *rp;
    int s = -1;
    char *request = NULL;
    size_t req_sz;
    char buf[4096];
    size_t total_recv = 0;
    char *response = NULL;
    size_t response_cap = 0;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &ai) != 0) {
        perror("getaddrinfo");
        return -1;
    }

    for (rp = ai; rp; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == -1) continue;
        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(s);
        s = -1;
    }
    if (s == -1) {
        fprintf(stderr, "connect failed to %s:%s\n", host, port);
        goto out;
    }

    /* Build request */
    const char *ct = content_type ? content_type : "application/json";
    size_t body_len = body ? strlen(body) : 0;
    req_sz = 256 + body_len;
    request = malloc(req_sz);
    if (!request) goto out;
    snprintf(request, req_sz,
             "POST %s HTTP/1.1\r\n"
             "Host: %s:%s\r\n"
             "User-Agent: airbotz-actions/1.0\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             path, host, port, ct, (size_t)body_len, body ? body : "");
    /* send all */
    size_t sent = 0;
    size_t tosend = strlen(request);
    while (sent < tosend) {
        ssize_t n = send(s, request + sent, tosend - sent, 0);
        if (n <= 0) { perror("send"); goto out; }
        sent += n;
    }

    /* receive */
    while (1) {
        ssize_t n = recv(s, buf, sizeof(buf), 0);
        if (n < 0) {
            perror("recv");
            goto out;
        }
        if (n == 0) break;
        if (total_recv + n + 1 > response_cap) {
            size_t newcap = (response_cap == 0) ? (n + 1024) : (response_cap * 2 + n);
            char *tmp = realloc(response, newcap);
            if (!tmp) { fprintf(stderr, "realloc failed\n"); goto out; }
            response = tmp;
            response_cap = newcap;
        }
        memcpy(response + total_recv, buf, n);
        total_recv += n;
    }
    if (response) response[total_recv] = '\0';

    /* Return */
    if (resp_out) *resp_out = response;
    if (resp_len_out) *resp_len_out = total_recv;
    response = NULL; /* ownership moved */
    rv = 0;

out:
    if (s != -1) close(s);
    freeaddrinfo(ai);
    free(request);
    free(response);
    return rv;
}

/* Build JSON payload for Ollama chat API, including model (from OLLAMA_MODEL or default).
   Escapa comillas/backslashes/newlines minimally. Caller must free the returned string. */
static const char *default_ollama_model(void) {
    const char *m = getenv("OLLAMA_MODEL");
    return (m && m[0]) ? m : "tinyllama:latest";
}

static char *build_chat_payload(const char *prompt) {
    const char *model = default_ollama_model();
    /* JSON template includes model, messages and max_tokens */
    const char *fmt = "{\"model\":\"%s\",\"messages\":[{\"role\":\"user\",\"content\":\"%s\"}],\"max_tokens\":512}";

    /* Escape prompt content minimally */
    size_t len = prompt ? strlen(prompt) : 0;
    size_t cap = len * 2 + 512;
    char *esc = malloc(cap);
    if (!esc) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len && j + 1 < cap; ++i) {
        char c = prompt[i];
        if (c == '\\' || c == '\"') {
            if (j + 2 >= cap) break;
            esc[j++] = '\\';
            esc[j++] = c;
        } else if (c == '\n') {
            if (j + 2 >= cap) break;
            esc[j++] = '\\';
            esc[j++] = 'n';
        } else {
            esc[j++] = c;
        }
    }
    esc[j] = '\0';

    size_t needed = strlen(fmt) + strlen(model) + strlen(esc) + 1;
    char *payload = malloc(needed);
    if (!payload) { free(esc); return NULL; }
    snprintf(payload, needed, fmt, model, esc);
    free(esc);
    return payload;
}

/* Read last N lines from ALERT_FILE. Returns heap string (caller must free). */
static char *read_last_n_lines(const char *path, int n) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    /* We'll seek from end and gather bytes until we have enough newlines */
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long pos = ftell(f);
    if (pos <= 0) { fclose(f); return NULL; }

    int lines = 0;
    long cur = pos - 1;
    size_t bufcap = 4096;
    char *buf = malloc(bufcap);
    if (!buf) { fclose(f); return NULL; }
    size_t buflen = 0;

    while (cur >= 0 && lines <= n) {
        if (fseek(f, cur, SEEK_SET) != 0) break;
        int c = fgetc(f);
        if (c == '\n') lines++;
        if (buflen + 2 > bufcap) {
            char *tmp = realloc(buf, bufcap * 2);
            if (!tmp) break;
            buf = tmp; bufcap *= 2;
        }
        buf[buflen++] = (char)c;
        cur--;
    }
    if (buflen == 0) { free(buf); fclose(f); return NULL; }
    /* reverse buffer */
    char *out = malloc(buflen + 1);
    if (!out) { free(buf); fclose(f); return NULL; }
    for (size_t i = 0; i < buflen; ++i) out[i] = buf[buflen - 1 - i];
    out[buflen] = '\0';
    free(buf);
    fclose(f);
    return out;
}

/* Menu actions */

static void action_analizar(void) {
    char choice[8];
    printf("Analizar (1=line input, 2=ultimas 20 alertas): ");
    if (!fgets(choice, sizeof(choice), stdin)) return;
    int c = atoi(choice);
    char prompt[8192];
    prompt[0] = '\0';

    if (c == 1) {
        printf("Introduce texto a analizar: ");
        if (!fgets(prompt, sizeof(prompt), stdin)) return;
        /* strip trailing newline */
        size_t L = strlen(prompt);
        if (L && prompt[L-1] == '\n') prompt[L-1] = '\0';
    } else {
        char *lines = read_last_n_lines(ALERT_FILE, 20);
        if (!lines) {
            printf("No se pudo leer %s\n", ALERT_FILE);
            return;
        }
        snprintf(prompt, sizeof(prompt),
                 "Analiza los siguientes alerts y resume posibles ataques, IPs sospechosas y acciones recomendadas:\n\n%s", lines);
        free(lines);
    }

    const char *addr = get_ollama_addr();
    char *host = NULL, *port = NULL;
    if (split_hostport(addr, &host, &port) != 0) {
        fprintf(stderr, "OLLAMA_ADDR inválido: %s\n", addr);
        return;
    }

    char *payload = build_chat_payload(prompt);
    if (!payload) { fprintf(stderr, "payload error\n"); free(host); free(port); return; }

    char *resp = NULL;
    size_t resp_len = 0;
    if (http_post(host, port, "/api/chat", "application/json", payload, &resp, &resp_len) == 0) {
        printf("\n--- Respuesta del modelo ---\n");
        if (resp_len) {
            /* Skip HTTP headers: find double CRLF */
            char *body = strstr(resp, "\r\n\r\n");
            if (body) body += 4;
            else body = resp;
            printf("%s\n", body);
        } else {
            printf("(respuesta vacía)\n");
        }
        free(resp);
    } else {
        fprintf(stderr, "Error al comunicarse con Ollama\n");
    }

    free(payload);
    free(host); free(port);
}

static void action_banear(void) {
    char ip[MAX_INPUT];
    printf("IP a banear: ");
    if (!fgets(ip, sizeof(ip), stdin)) return;
    size_t L = strlen(ip); if (L && ip[L-1]=='\n') ip[L-1]='\0';
    if (!is_valid_ipv4(ip)) {
        printf("IP inválida: %s\n", ip);
        return;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pfctl -t bruteforce -T add %s", ip);
    int rc = system(cmd);
    printf("Comando: %s -> rc=%d\n", cmd, rc);
}

static void action_desbanear(void) {
    char ip[MAX_INPUT];
    printf("IP a desbanear: ");
    if (!fgets(ip, sizeof(ip), stdin)) return;
    size_t L = strlen(ip); if (L && ip[L-1]=='\n') ip[L-1]='\0';
    if (!is_valid_ipv4(ip)) {
        printf("IP inválida: %s\n", ip);
        return;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pfctl -t bruteforce -T delete %s", ip);
    int rc = system(cmd);
    printf("Comando: %s -> rc=%d\n", cmd, rc);
}

/* "Reentrenar" es limitado — Ollama local no admite training desde HTTP API; here we simulate by sending examples and asking model to produce rules.
   We POST the recent alerts and request a compact ruleset response; user can then choose to persist it manually. */
static void action_reentrenar(void) {
    printf("Recolectando ultimas 200 lineas para 'reentrenar' (simulado)...\n");
    char *lines = read_last_n_lines(ALERT_FILE, 200);
    if (!lines) { printf("No se pudieron leer alertas.\n"); return; }

    char prompt[16384];
    snprintf(prompt, sizeof(prompt),
             "USAGE: You are a security assistant. Based on these recent alerts, output:\n"
             "1) A short summary of attack types.\n"
             "2) Up to 20 simple detection rules (one per line), each tiny (e.g. contains 'wp-login' AND status 200 -> suspect).\n"
             "3) Up to 10 IPs that look most suspicious (list only ips).\n\n"
             "ALERTS:\n%s\n\nRespond in plain text.", lines);

    free(lines);

    const char *addr = get_ollama_addr();
    char *host = NULL, *port = NULL;
    if (split_hostport(addr, &host, &port) != 0) {
        fprintf(stderr, "OLLAMA_ADDR inválido: %s\n", addr);
        return;
    }
    char *payload = build_chat_payload(prompt);
    if (!payload) { fprintf(stderr, "payload error\n"); free(host); free(port); return; }

    char *resp = NULL;
    size_t resp_len = 0;
    if (http_post(host, port, "/api/chat", "application/json", payload, &resp, &resp_len) == 0) {
        printf("\n--- Reentrenamiento (simulado) - salida del modelo ---\n");
        if (resp_len) {
            char *body = strstr(resp, "\r\n\r\n");
            if (body) body += 4;
            else body = resp;
            printf("%s\n", body);
        } else printf("(sin respuesta)\n");
        free(resp);
    } else {
        fprintf(stderr, "Error comunicándose con Ollama\n");
    }

    free(payload);
    free(host); free(port);
}

int actions_main(void) {
    char choice[8];
    while (1) {
        printf("\n=== Airbotz - Ollama Actions ===\n");
        printf("1) Analizar\n");
        printf("2) Banear IP\n");
        printf("3) Desbanear IP\n");
        printf("4) Reentrenar (simulado)\n");
        printf("0) Salir\n");
        printf("Selecciona: ");
        if (!fgets(choice, sizeof(choice), stdin)) break;
        int c = atoi(choice);
        switch (c) {
            case 1: action_analizar(); break;
            case 2: action_banear(); break;
            case 3: action_desbanear(); break;
            case 4: action_reentrenar(); break;
            case 0: printf("Saliendo.\n"); return 0;
            default: printf("Opcion invalida.\n");
        }
    }
    return 0;
}
