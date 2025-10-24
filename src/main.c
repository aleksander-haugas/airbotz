#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>

#include "../include/state_manager.h"
#include "../include/parser_nginx.h"
#include "../include/parser_vsftpd.h"
#include "../include/parser_sshd.h"
#include "../include/parser_pflog.h" // NUEVO: Para el monitoreo de PF
#include "../include/rules.h"

// Prototipo de status para CLI
void show_status(void);
int actions_main(void); // modo interactivo

#define READ_BUFFER_SIZE 65536    /* más grande para eficiencia */
#define LINE_BUFFER_SIZE 4096
#define MAX_LOGS         8
#define MAX_EVENTS_BATCH 32

// Timers de Kqueue
#define TIMER_ID_CLEANUP 1        // Timer para limpieza de estado
#define TIMER_ID_INTEGRITY 2      // Timer para auditoría de rkhunter
#define CLEANUP_INTERVAL_MS (1 * 3600 * 1000)    // 1 hora en milisegundos
#define INTEGRITY_INTERVAL_MS (24 * 3600 * 1000) // 24 horas en milisegundos

static volatile sig_atomic_t keep_running = 1;

typedef struct {
    int fd;
    char path[256];
    void (*parser)(const char *line);

    /* buffer de línea individual */
    char line_buf[LINE_BUFFER_SIZE];
    size_t line_len;
} LogWatcher;

static LogWatcher watchers[MAX_LOGS];
static int watcher_count = 0;

/* ---------- Señales ---------- */
static void handle_signal(int sig) {
    (void)sig;
    keep_running = 0;
}

/* ---------- Reapertura de logs ---------- */
static int reopen_log(LogWatcher *w) {
    int new_fd = open(w->path, O_RDONLY);
    if (new_fd < 0) return -1;
    close(w->fd);
    lseek(new_fd, 0, SEEK_END);
    w->fd = new_fd;
    w->line_len = 0; // reiniciar buffer
    return 0;
}

/* ---------- Registro de logs ---------- */
static int add_log(const char *path, void (*parser)(const char *)) {
    if (watcher_count >= MAX_LOGS) return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[airbotz] No se pudo abrir %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (lseek(fd, 0, SEEK_END) < 0) {
        perror("lseek");
        close(fd);
        return -1;
    }

    LogWatcher *w = &watchers[watcher_count++];
    w->fd = fd;
    w->parser = parser;
    strncpy(w->path, path, sizeof(w->path) - 1);
    w->path[sizeof(w->path)-1] = '\0';
    w->line_len = 0;
    return 0;
}

/* ---------- Bucle principal ---------- */
int main(int argc, char *argv[]) {
    rules_init("/usr/local/etc/airbotz.conf", NULL);

    /* CLI status */
    if (argc == 2 && strcmp(argv[1], "status") == 0) {
        // No cargamos el estado aquí para evitar el mensaje de 'iniciando limpio'.
        // show_status() debe leer directamente de los archivos de alerta/ban.
        show_status();
        return 0;
    }

    /* CLI actions */
    if (argc >= 2 && strcmp(argv[1], "actions") == 0) {
        // Ejecución de comandos de acción, no requiere carga de estado completo
        return actions_main();
    }
    
    // ----------------------------------------------------------------------
    // INICIALIZACIÓN DEL DEMONIO (solo para el modo de monitoreo)
    // ----------------------------------------------------------------------

    // AÑADIR: Cargar el estado persistente (MOVIDO AQUÍ)
    if (state_manager_init() != 0) {
        fprintf(stderr, "[airbotz] Fallo crítico al cargar el estado. Abortando.\n");
        return 1;
    }

    /* Logs según argumentos */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "nginx") == 0) {
            add_log("/var/log/nginx/access.log", parse_nginx_line);
        } else if (strcmp(argv[i], "vsftpd") == 0) {
            add_log("/var/log/vsftpd.log", parse_vsftpd_line);
        } else if (strcmp(argv[i], "sshd") == 0) {
            add_log("/var/log/auth.log", parse_sshd_line);
        } else if (strcmp(argv[i], "pflog") == 0) { // NUEVA INTEGRACIÓN
            // El pflog monitor se inicia como una rutina aparte, no como un log file watcher
            start_pflog_monitor();
            fprintf(stderr, "[airbotz] Monitoreo de PFlog iniciado.\n");
        }
    }
    //add_log("/var/log/airbotz_alerts.json", parse_alert_json_line);

    if (watcher_count == 0 && (argc < 2 || strcmp(argv[1], "pflog") != 0)) {
        fprintf(stderr, "[airbotz] No se especificaron servicios a monitorear (o solo pflog).\n");
        if (argc < 2) return 1;
    }

    int kq = kqueue();

/* AÑADIR: Registro de Timers del Reloj */
struct kevent timer_ev[2];
int timer_count = 0;

// Timer 1: Limpieza de Contadores de Estado (cada 1 hora)
EV_SET(&timer_ev[timer_count++], TIMER_ID_CLEANUP, EVFILT_TIMER, EV_ADD | EV_ENABLE,
        0, CLEANUP_INTERVAL_MS, NULL);

// Timer 2: Auditoría de Integridad (cada 24 horas)
EV_SET(&timer_ev[timer_count++], TIMER_ID_INTEGRITY, EVFILT_TIMER, EV_ADD | EV_ENABLE,
        0, INTEGRITY_INTERVAL_MS, NULL);

if (kevent(kq, timer_ev, timer_count, NULL, 0, NULL) == -1) {
    perror("kevent register timers");
    return 1;
}

    if (kq == -1) {
        perror("kqueue");
        return 1;
    }

    for (int i = 0; i < watcher_count; i++) {
        struct kevent ev;
        EV_SET(&ev, watchers[i].fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
                NOTE_WRITE | NOTE_DELETE | NOTE_RENAME, 0, &watchers[i]);
        if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1) {
            perror("kevent register");
            return 1;
        }
    }

    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    char read_buf[READ_BUFFER_SIZE];

    while (keep_running) {
        struct kevent events[MAX_EVENTS_BATCH];
        int nev = kevent(kq, NULL, 0, events, MAX_EVENTS_BATCH, NULL);

        if (nev == -1) {
            if (errno == EINTR) continue;
            perror("kevent wait");
            break;
        }

        for (int e = 0; e < nev; e++) {
            struct kevent *kev = &events[e];

            /* AÑADIR: Manejo de Timers */
            if (kev->filter == EVFILT_TIMER) {
                if (kev->ident == TIMER_ID_CLEANUP) {
                    // Limpia contadores viejos del State Manager (persistencia)
                    state_manager_cleanup_old();
                    // Limpia bans expirados de la tabla PF (airbotz_temp)
                    rules_cleanup_expired_bans();
                } else if (kev->ident == TIMER_ID_INTEGRITY) {
                    // Lógica futura: Aquí se ejecutará la auditoría de rkhunter.
                    // integrity_audit_run();
                }
                continue; // Procesar el siguiente evento, no es un log
            }

            LogWatcher *w = (LogWatcher *)kev->udata;

            if (kev->fflags & (NOTE_DELETE | NOTE_RENAME)) {
                if (reopen_log(w) == 0) {
                    struct kevent ev;
                    EV_SET(&ev, w->fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
                            NOTE_WRITE | NOTE_DELETE | NOTE_RENAME, 0, w);
                    kevent(kq, &ev, 1, NULL, 0, NULL);
                }
                continue;
            }

            if (!(kev->fflags & NOTE_WRITE)) continue;

            ssize_t n;
            while ((n = read(w->fd, read_buf, sizeof(read_buf))) > 0) {
                for (ssize_t i = 0; i < n; i++) {
                    char c = read_buf[i];
                    if (c == '\n' || w->line_len == LINE_BUFFER_SIZE - 1) {
                        w->line_buf[w->line_len] = '\0';
                        if (w->line_len > 0) {
                            w->parser(w->line_buf);
                        }
                        w->line_len = 0;
                    } else {
                        w->line_buf[w->line_len++] = c;
                    }
                }
            }
        }
    }

    for (int i = 0; i < watcher_count; i++) {
        close(watchers[i].fd);
    }
    close(kq);
    rules_shutdown();
    // AÑADIR: Guardar el estado persistente antes de salir
    state_manager_save();
    return 0;
}

