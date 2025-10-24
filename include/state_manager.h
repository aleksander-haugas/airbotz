#ifndef _STATE_MANAGER_H_
#define _STATE_MANAGER_H_

#include <sys/types.h>
#include <stdint.h>
#include <time.h>

// Definiciones de longitud para strings, basadas en rules.c
#define SERVICE_MAX_LEN 32
#define EVENT_MAX_LEN 64

// Máximo de direcciones IP únicas que el sistema rastreará.
// Un valor razonable para evitar el uso excesivo de memoria.
#define MAX_ATTACKERS 4096

// Ruta al archivo de estado persistente.
// Usamos /var/db/ para datos de daemons en FreeBSD.
#define STATE_FILE_PATH "/var/db/airbotz/state.dat"

// Estructura para el contador de ataques por IP.
// Es la clave para la detección basada en tiempo (ej. 5 fallos en 60s).
typedef struct {
    uint32_t ip_addr;               // Dirección IP en formato binario (network byte order)
    char service_name[SERVICE_MAX_LEN]; // *** NUEVO: Servicio asociado (ssh, http) ***
    char event_type[EVENT_MAX_LEN];     // *** NUEVO: Tipo de evento específico (failed_login, invalid_user) ***
    time_t first_attempt_ts;        // Timestamp del primer fallo en el ciclo actual
    unsigned int failure_count;     // Contador de fallos
    time_t last_attempt_ts;       // último intento observado
    unsigned int escalation_level; // cuántas veces alcanzó el umbral (para escalar bans)
} AttackCounter;

// Estructura de estado global (Airbotz State Table)
typedef struct {
    size_t counter_count;               // Número actual de AttackCounters
    AttackCounter counters[MAX_ATTACKERS]; // Array estático de contadores
} AirbotzState;

// Funciones a exponer en el resto del programa

// Inicializa la estructura de estado global (carga desde disco).
int state_manager_init(void);

// Guarda el estado actual en el disco (llamado al salir del daemon).
void state_manager_save(void);

// Busca o crea un contador para el triplete (IP, Servicio, Evento).
// *** MODIFICADO: Ahora requiere service y event ***
AttackCounter *state_manager_get_counter(uint32_t ip_addr, const char *service, const char *event);

// Limpia las entradas antiguas (llamado por el timer de kqueue).
void state_manager_cleanup_old(void);

#endif /* _STATE_MANAGER_H_ */
