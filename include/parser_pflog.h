#ifndef PARSER_PFLOG_H
#define PARSER_PFLOG_H

/*
 * Monitoreo de logs binarios de PF.
 * Esto requiere libreras del sistema como libpcap y threading (pthread).
 */
void start_pflog_monitor(void);

/*
 * Estructura de evento de PF (simplificada)
 * Usada internamente para estandarizar los datos capturados.
 */
typedef struct {
    char timestamp[64];
    char src_ip[64];
    char dst_ip[64];
    int action; // PF_PASS (1), PF_DROP (2), etc.
    char reason[128]; // Motivo del drop (por ejemplo, el nombre de la tabla)
    char proto[16]; // Protocolo (TCP, UDP, ICMP, etc.)
} pflog_event_t;

#endif // PARSER_PFLOG_H
