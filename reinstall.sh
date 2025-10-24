#!/bin/sh
# ==============================================================================
# AIRBOTZ REINSTALL RITUAL
# Detiene, limpia, recompila y reinicia el servicio con logs purgados.
# ==============================================================================

AIRBOTZ_DIR="/airbotz"
STATE_FILE="/var/db/airbotz/state.dat"
CONSOLE_LOG_FILE="/var/log/airbotz.log"
PANEL_LOG_FILE="/var/log/airbotz_alerts.json"
SERVICE_NAME="airbotz"

log() {
    echo "[AIRBOTZ] $1"
}

log "1. Deteniendo servicio: $SERVICE_NAME"
service "$SERVICE_NAME" stop 2>/dev/null || log "Advertencia: No se pudo detener $SERVICE_NAME"

log "2. Navegando a $AIRBOTZ_DIR"
cd "$AIRBOTZ_DIR" || {
    log "Error: No se pudo acceder a $AIRBOTZ_DIR"
    exit 1
}

log "3. Limpiando binarios (make clean)"
make clean || log "Advertencia: 'make clean' falló"

log "4. Desinstalando artefactos previos (make deinstall)"
make deinstall 2>/dev/null || log "Advertencia: 'make deinstall' no disponible"

log "5. Purgando estado persistente y logs"
rm -f "$STATE_FILE"
: > "$CONSOLE_LOG_FILE"
: > "$PANEL_LOG_FILE"

log "6. Compilando proyecto (make)"
make || {
    log "Error: Falló la compilación"
    exit 1
}

log "7. Instalando binarios (make install)"
make install || log "Advertencia: 'make install' falló"

log "8. Reiniciando servicio: $SERVICE_NAME"
service "$SERVICE_NAME" start 2>/dev/null || log "Advertencia: No se pudo iniciar $SERVICE_NAME"

log "Reinstalación completa. Artefacto listo para prueba."

