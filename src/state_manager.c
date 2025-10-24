#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../include/state_manager.h"

// Variable global para almacenar todo el estado de Airbotz en memoria.
static AirbotzState airbotz_state;

/* ------------------ Funciones de Utilidad (Hash/Busqueda) ------------------ */

// Funcin simple de hash para encontrar la posicin aproximada de la IP (optimizacin).
// En produccin, se usara un hash map ms robusto, pero para un array esttico, esto funciona.
static size_t hash_ip(uint32_t ip_addr) {
    return (size_t)(ip_addr % MAX_ATTACKERS);
}

// Busca un contador existente para el triplete (IP, Servicio, Evento)
static AttackCounter *find_counter(uint32_t ip_addr, const char *service, const char *event) {
    size_t start_index = hash_ip(ip_addr);

    for (size_t i = 0; i < MAX_ATTACKERS; i++) {
        size_t index = (start_index + i) % MAX_ATTACKERS;
        AttackCounter *counter = &airbotz_state.counters[index];

        if (counter->ip_addr == ip_addr) {
            // Comprobar Service y Event Type para la unicidad
      if (strcmp(counter->service_name, service) == 0 &&
        strcmp(counter->event_type, event) == 0) {
        return counter; // Encontrado
      }
        }
        if (counter->ip_addr == 0) {
            return NULL; // Slot vaco (no encontrado)
        }
    }
    return NULL; // La tabla est llena o no se encontr
}

/* ------------------ Funciones de Carga/Guardado ------------------ */
int state_manager_init(void) {
    // 1. Inicializar la estructura de memoria
    memset(&airbotz_state, 0, sizeof(AirbotzState));

    // 2. Intentar cargar desde el disco
    FILE *f = fopen(STATE_FILE_PATH, "rb");
    if (f == NULL) {
        // No es un error crtico si el archivo no existe (primera ejecucin)
        if (errno == ENOENT) {
            fprintf(stderr, "[airbotz] Estado no encontrado. Iniciando limpio.\n");
            return 0;
        }
        perror("[airbotz] Error al abrir el estado para lectura");
        return -1;
    }

    // Leer toda la estructura de una vez
    if (fread(&airbotz_state, sizeof(AirbotzState), 1, f) != 1) {
        perror("[airbotz] Error al leer el estado. Corrompido?");
        fclose(f);
        // Podramos intentar recuperar, pero por seguridad, iniciamos limpio.
        memset(&airbotz_state, 0, sizeof(AirbotzState));
        return -1;
    }

    fclose(f);
    fprintf(stderr, "[airbotz] Estado cargado con %zu contadores.\n", airbotz_state.counter_count);
    return 0;
}

void state_manager_save(void) {
    // 1. Crear el directorio si no existe
    if (mkdir("/var/db/airbotz", 0700) == -1 && errno != EEXIST) {
        perror("[airbotz] Error al crear directorio de estado");
        return;
    }

    // 2. Abrir/Crear archivo en modo binario
    FILE *f = fopen(STATE_FILE_PATH, "wb");
    if (f == NULL) {
        perror("[airbotz] Error al abrir el estado para escritura");
        return;
    }

    // 3. Escribir toda la estructura
    if (fwrite(&airbotz_state, sizeof(AirbotzState), 1, f) != 1) {
        perror("[airbotz] Error al escribir el estado. Prdida de datos.");
    }

    // 4. Forzar el volcado a disco (seguridad)
    fflush(f);
    fsync(fileno(f));

    fclose(f);
    fprintf(stderr, "[airbotz] Estado guardado correctamente.\n");
}

/* ------------------ Funciones de Gestin de Contadores ------------------ */
AttackCounter *state_manager_get_counter(uint32_t ip_addr, const char *service, const char *event) {
    if (ip_addr == 0) return NULL; // No rastrear 0.0.0.0

    // 1. Buscar si ya existe el triplete (IP, Servicio, Evento)
  AttackCounter *counter = find_counter(ip_addr, service, event);
  if (counter != NULL) {
    return counter;
  }

  // 2. No existe, intentar crear uno nuevo
  if (airbotz_state.counter_count >= MAX_ATTACKERS) {
    fprintf(stderr, "[airbotz] ADVERTENCIA: Tabla de atacantes llena. No se puede rastrear %u.\n", ip_addr);
    return NULL;
  }

  // Usar la ranura libre (donde ip_addr == 0)
  size_t start_index = hash_ip(ip_addr);
  for (size_t i = 0; i < MAX_ATTACKERS; i++) {
    size_t index = (start_index + i) % MAX_ATTACKERS;
    AttackCounter *new_counter = &airbotz_state.counters[index];

    if (new_counter->ip_addr == 0) {
      new_counter->ip_addr = ip_addr;
            strncpy(new_counter->service_name, service, SERVICE_MAX_LEN - 1);
            new_counter->service_name[SERVICE_MAX_LEN - 1] = '\0';
            strncpy(new_counter->event_type, event, EVENT_MAX_LEN - 1);
            new_counter->event_type[EVENT_MAX_LEN - 1] = '\0';
      new_counter->first_attempt_ts = time(NULL);
      new_counter->failure_count = 0;
      airbotz_state.counter_count++;
      return new_counter;
    }
  }

  return NULL;
}

void state_manager_cleanup_old(void) {
    time_t now = time(NULL);
    // Definir el tiempo de vida (TTL) para los contadores (ej. 1 hora = 3600s)
    // Las IPs con fallos antiguos se borran, obligando a un atacante a reiniciar el ciclo.
    const time_t COUNTER_TTL = 3600;

    size_t cleaned_count = 0;

    for (size_t i = 0; i < MAX_ATTACKERS; i++) {
        AttackCounter *counter = &airbotz_state.counters[i];

        if (counter->ip_addr != 0) { // Si el slot est en uso
            // Si el primer intento es ms antiguo que el TTL
            if (now - counter->first_attempt_ts > COUNTER_TTL) {
                // Limpiar el slot
                memset(counter, 0, sizeof(AttackCounter));
                airbotz_state.counter_count--;
                cleaned_count++;
            }
        }
    }

    if (cleaned_count > 0) {
        fprintf(stderr, "[airbotz] Limpieza de estado: %zu contadores expirados eliminados.\n", cleaned_count);
    }
}

