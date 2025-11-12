// Headers estándar
// =========================================================================
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <stdarg.h>

// Headers para PF y pcap en FreeBSD
// =========================================================================
/* 
    So basically all this code is for FreeBSD tested only. 
    If you want to port it to other OS, you will need to adapt the code.
*/
#ifdef __WIN64__
    // Headers específicos de Windows
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h> // Para funciones de red más modernas
    #error "This code is intended for FreeBSD systems only."
#endif
// Incluye solo en sistemas BSD
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    #include <unistd.h>
    #include <pthread.h>
    #include <pcap/pcap.h>
    #include <net/if_pflog.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/ip6.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/ip_icmp.h>
    #include <arpa/inet.h>
#endif

// Headers for Airbotz project
// =========================================================================
#include "../include/parser_pflog.h"
#include "../include/rules.h"
#include "../include/state_manager.h"

// Configuration and constants (Check these values on your airbotz.conf)
// =========================================================================
/*
    Some of this values can be configured on airbotz.conf file.
    Check the documentation for more information.

    You can adjust these values according to your needs.
    For now this is very strict values for testing purposes.
    and can generate a lot of false positives on busy networks.
    or block your entire network if misconfigured.
*/
#define WINDOW_SEC   60     // ventana de observación (segundos)
#define THRESHOLD    15     // puertos distintos para considerarlo escaneo
#define MAX_EVENTS   512    // tamaño del buffer de eventos
#define DEBUG_PFLOG  0      // 1 para debug, 0 para producción

// Estructura para entradas de alertas
typedef struct {
    uint32_t ip;
    time_t last_alert;
} alert_entry_t;

// Estructura para eventos de puertos
typedef struct {
    uint16_t port;
    time_t ts;
} port_event_t;

// Estructura para seguimiento de escaneos por IP
typedef struct ip_scan {
    uint32_t ip_h;
    port_event_t events[MAX_EVENTS];
    size_t head;  // índice del primer evento válido
    size_t count; // número de eventos válidos
    struct ip_scan *next;
} ip_scan_t;

static ip_scan_t *scan_list = NULL; // lista enlazada de IPs
static pthread_mutex_t scan_lock = PTHREAD_MUTEX_INITIALIZER;

/* Convierte IP host-order -> string */
static void ip_h_to_str(uint32_t ip_h, char *buf, size_t buflen) {
    struct in_addr ina;
    ina.s_addr = htonl(ip_h);
    inet_ntop(AF_INET, &ina, buf, buflen);
}

// Busca o crea una entrada de escaneo para una IP dada
static ip_scan_t *scan_find_or_create(uint32_t ip_h) {
    ip_scan_t *entry = scan_list;
    while (entry) {
        if (entry->ip_h == ip_h) return entry;
        entry = entry->next;
    }
    // Crear nueva entrada
    entry = calloc(1, sizeof(ip_scan_t));
    if (!entry) return NULL;
    entry->ip_h = ip_h;
    entry->next = scan_list;
    scan_list = entry;
    return entry;
}

// This function removes old events from the scan entry
static void scan_cleanup_old(ip_scan_t *entry, time_t now) {
    while (entry->count > 0) {
        size_t idx = entry->head % MAX_EVENTS;
        if (now - entry->events[idx].ts <= WINDOW_SEC) break;
        entry->head = (entry->head + 1) % MAX_EVENTS;
        entry->count--;
    }
}

// Count unique ports in the current window
static size_t scan_count_unique_ports(ip_scan_t *entry) {
    uint16_t seen[MAX_EVENTS];
    size_t seen_cnt = 0;
    for (size_t i = 0; i < entry->count; i++) {
        size_t idx = (entry->head + i) % MAX_EVENTS;
        uint16_t p = entry->events[idx].port;
        int found = 0;
        for (size_t j = 0; j < seen_cnt; j++) {
            if (seen[j] == p) { found = 1; break; }
        }
        if (!found) seen[seen_cnt++] = p;
    }
    return seen_cnt;
}

// Print TCP flags as string (e.g., "S", "SA", "FPR", etc.)
static void print_tcp_flags(uint8_t th_flags, char *buf) {
    size_t pos = 0;
    if (th_flags & TH_SYN) buf[pos++] = 'S';
    if (th_flags & TH_ACK) buf[pos++] = 'A';
    if (th_flags & TH_FIN) buf[pos++] = 'F';
    if (th_flags & TH_RST) buf[pos++] = 'R';
    if (th_flags & TH_PUSH) buf[pos++] = 'P';
    if (th_flags & TH_URG) buf[pos++] = 'U';
    buf[pos] = '\0';
}

// Dump de payload en hex + ASCII
static void dump_payload(const u_char *payload, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        fprintf(stderr, "    ");
        for (size_t j = 0; j < 16 && i + j < len; j++)
            fprintf(stderr, "%02x ", payload[i + j]);

        fprintf(stderr, "  ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = payload[i + j];
            fprintf(stderr, "%c", (c >= 32 && c <= 126) ? c : '.');
        }
        fprintf(stderr, "\n");
    }
}

// Portscan detection logic for SYN packets
static void scan_record_syn(uint32_t ip_h, uint16_t dport) {
    time_t now = time(NULL);

    // Lock the scan list
    pthread_mutex_lock(&scan_lock);
    ip_scan_t *entry = scan_find_or_create(ip_h);
    if (!entry) { pthread_mutex_unlock(&scan_lock); return; }

    // Limpiar eventos viejos
    scan_cleanup_old(entry, now);

    // Añadir nuevo evento
    size_t insert_idx = (entry->head + entry->count) % MAX_EVENTS;
    entry->events[insert_idx].port = dport;
    entry->events[insert_idx].ts = now;
    
    // Actualizar conteo
    if (entry->count < MAX_EVENTS) entry->count++;
    else entry->head = (entry->head + 1) % MAX_EVENTS;
    
    // Contar puertos únicos
    size_t unique_ports = scan_count_unique_ports(entry);
    if (unique_ports >= THRESHOLD) {
        char ipbuf[INET_ADDRSTRLEN];
        ip_h_to_str(ip_h, ipbuf, sizeof(ipbuf));

        /* Obtener rango de puertos para info */
        uint16_t minp = 0xffff, maxp = 0;
        for (size_t i = 0; i < entry->count; i++) {
            size_t idx = (entry->head + i) % MAX_EVENTS;
            uint16_t p = entry->events[idx].port;
            if (p < minp) minp = p;
            if (p > maxp) maxp = p;
        }
        if (minp == 0xffff) minp = maxp = 0;

        char info[256];
        snprintf(info, sizeof(info),
            "portscan detected: %zu unique ports (window=%ds) ports=%u-%u",
            unique_ports, WINDOW_SEC, minp, maxp);

        // call rules handler
        rules_handle_action("pflog", "portscan", ipbuf, info);

        /* JSON opcional */
        FILE *out = fopen("/var/log/airbotz_alerts.json", "a");
        if (out) {
            char ts[64];
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));
            fprintf(out,
                "{\"timestamp\":\"%s\",\"service\":\"pflog\",\"event\":\"portscan\",\"ip\":\"%s\",\"info\":\"%s\"}\n",
                ts, ipbuf, info);
            fclose(out);
        }

        /* RESET de la ventana */
        entry->head = 0;
        entry->count = 0;
    }

    // Unlock the scan list
    pthread_mutex_unlock(&scan_lock);
}

// TCP parser común (versión con state_manager)
// Detecta SYN sin ACK para portscan y flood
static void decode_tcp(const u_char *payload, size_t l4_len, uint32_t src_ip_h) {
    if (l4_len < sizeof(struct tcphdr)) return;
    struct tcphdr tcph;
    memcpy(&tcph, payload, sizeof(tcph));

    int is_syn = (tcph.th_flags & TH_SYN) != 0;
    int is_ack = (tcph.th_flags & TH_ACK) != 0;

    /* Detectamos SYN sin ACK (inicio de conexión) */
    if (is_syn && !is_ack) {
        /* 1) Portscan (tu lógica actual) */
        scan_record_syn(src_ip_h, ntohs(tcph.th_dport));

        /* 2) Flood detection: tratar cada SYN como un "evento" para syn_flood.
              Llamamos a rules_handle_action por cada SYN para que el engine
              cuente con su ventana/umbral. */
        char ipbuf[INET_ADDRSTRLEN];
        ip_h_to_str(src_ip_h, ipbuf, sizeof(ipbuf));
        rules_handle_action("pflog", "syn_flood", ipbuf, "SYN packet observed");
    }

    // Debug output in raw mode
    if (DEBUG_PFLOG) {
        size_t tcp_header_len = tcph.th_off * 4;
        char flags[8];
        print_tcp_flags(tcph.th_flags, flags);
        fprintf(stderr, "  TCP %u -> %u flags=%s hdrlen=%zu\n",
            ntohs(tcph.th_sport), ntohs(tcph.th_dport), flags, tcp_header_len);
        size_t payload_len = l4_len - tcp_header_len;
        if (payload_len > 0) dump_payload(payload + tcp_header_len, payload_len);
    }
}

// ICMP parser
static void decode_icmp(const u_char *payload, size_t l4_len, uint32_t src_ip_h) {
    if (l4_len < 2) return;
    #if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
        const struct icmp *icmp = (const struct icmp *)payload;
        unsigned int type = icmp->icmp_type;
        unsigned int code = icmp->icmp_code;
    #else
        const struct icmphdr *icmp = (const struct icmphdr *)payload;
        unsigned int type = icmp->type;
        unsigned int code = icmp->code;
    #endif

    char ipbuf[INET_ADDRSTRLEN];
    ip_h_to_str(src_ip_h, ipbuf, sizeof(ipbuf));
    char info[64];
    snprintf(info, sizeof(info), "ICMP type=%u code=%u", type, code);
    rules_handle_action("pflog", "icmp_flood", ipbuf, info);

    if (DEBUG_PFLOG) {
        fprintf(stderr, "  ICMP type=%u code=%u\n", type, code);
    }
}


// UDP parser común
static void decode_udp(const u_char *payload, size_t l4_len, uint32_t src_ip_h) {
    if (l4_len < sizeof(struct udphdr)) return;
    struct udphdr udph;
    memcpy(&udph, payload, sizeof(udph));

    /* Flood detection: cada UDP es un evento para udp_flood */
    char ipbuf[INET_ADDRSTRLEN];
    ip_h_to_str(src_ip_h, ipbuf, sizeof(ipbuf));
    rules_handle_action("pflog", "udp_flood", ipbuf, "UDP packet observed");

    if (DEBUG_PFLOG) {
        size_t payload_len = ntohs(udph.uh_ulen) - sizeof(struct udphdr);
        fprintf(stderr, "  UDP %u -> %u len=%zu\n",
            ntohs(udph.uh_sport), ntohs(udph.uh_dport), payload_len);
        if (payload_len > 0 && payload_len <= l4_len - sizeof(struct udphdr))
            dump_payload(payload + sizeof(struct udphdr), payload_len);
    }
}

// Decode paquete
static void decode_packet(const u_char *ptr, size_t caplen, sa_family_t af) {
    if (af == AF_INET) {
        if (caplen < sizeof(struct ip)) return;

        struct ip *iph = (struct ip *)ptr;
        size_t ip_header_len = iph->ip_hl * 4;
        if (caplen < ip_header_len) return;

        if (DEBUG_PFLOG) {
            char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &iph->ip_src, src, sizeof(src));
            inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof(dst));
            fprintf(stderr, "IPv4 %s -> %s proto=%d ttl=%d len=%d\n",
                src, dst, iph->ip_p, iph->ip_ttl, ntohs(iph->ip_len));
        }

        size_t l4_len = ntohs(iph->ip_len) - ip_header_len;
        const u_char *payload = ptr + ip_header_len;
        uint32_t src_ip_h = ntohl(iph->ip_src.s_addr);

        if (iph->ip_p == IPPROTO_TCP) {
            decode_tcp(payload, l4_len, src_ip_h);
        } else if (iph->ip_p == IPPROTO_UDP) {
            decode_udp(payload, l4_len, src_ip_h);
        } else if (iph->ip_p == IPPROTO_ICMP) {
            decode_icmp(payload, l4_len, src_ip_h);
        } else {
            if (DEBUG_PFLOG) fprintf(stderr, "  Protocolo no soportado: %d\n", iph->ip_p);
        }

    } else if (af == AF_INET6) {
        /* Si no usas IPv6, puedes mantener esto pero no lo ejecutarás. */
        if (caplen < sizeof(struct ip6_hdr)) return;
        struct ip6_hdr *ip6h = (struct ip6_hdr *)ptr;
        if (DEBUG_PFLOG) {
            char src6[INET6_ADDRSTRLEN], dst6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6h->ip6_src, src6, sizeof(src6));
            inet_ntop(AF_INET6, &ip6h->ip6_dst, dst6, sizeof(dst6));
            fprintf(stderr, "IPv6 %s -> %s proto=%d\n", src6, dst6, ip6h->ip6_nxt);
        }
        size_t l4_len = caplen - sizeof(struct ip6_hdr);
        const u_char *payload = ptr + sizeof(struct ip6_hdr);

        if (ip6h->ip6_nxt == IPPROTO_TCP) decode_tcp(payload, l4_len, 0);
        else if (ip6h->ip6_nxt == IPPROTO_UDP) decode_udp(payload, l4_len, 0);
        else if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
            /* Si quieres soporte ICMPv6, implementar decode_icmpv6 similar */
        } else {
            if (DEBUG_PFLOG) fprintf(stderr, "  Protocolo no soportado: %d\n", ip6h->ip6_nxt);
        }
    } else {
        if (DEBUG_PFLOG) fprintf(stderr, "Familia desconocida: %d\n", af);
    }
}

// Handler PFLOG
static void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user;
    if (pkthdr->caplen < sizeof(struct pfloghdr)) return;
    const struct pfloghdr *pfl = (const struct pfloghdr *)packet;

    char ifname[IFNAMSIZ + 1];
    memcpy(ifname, pfl->ifname, IFNAMSIZ);
    ifname[IFNAMSIZ] = '\0';

    if (DEBUG_PFLOG) {
        fprintf(stderr, "[pflog] iface=%s action=%d reason=%d af=%d caplen=%u\n",
            ifname, pfl->action, pfl->reason, pfl->af, pkthdr->caplen);
    }
    const u_char *ptr = packet + sizeof(struct pfloghdr);
    size_t caplen = pkthdr->caplen - sizeof(struct pfloghdr);

    decode_packet(ptr, caplen, pfl->af);
    if (DEBUG_PFLOG) {
        size_t dump_bytes_count = (caplen > 64) ? 64 : caplen;
        dump_payload(ptr, dump_bytes_count);
    }
}

// Hilo y funciones públicas
static pthread_t pflog_thread_id;
static int thread_running = 0;
static pcap_t *pflog_handle = NULL;

static void *pflog_thread_routine(void *arg) {
    (void)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pflog_handle = pcap_open_live("pflog0", 65535, 1, 1000, errbuf);
    if (!pflog_handle) {
        fprintf(stderr, "[pflog] ERROR: %s\n", errbuf);
        thread_running = 0;
        return NULL;
    }

    fprintf(stderr, "[pflog] Hilo de captura inicializado en pflog0\n");
    thread_running = 1;
    pcap_loop(pflog_handle, -1, packet_handler, NULL);

    pcap_close(pflog_handle);
    pflog_handle = NULL;
    thread_running = 0;
    fprintf(stderr, "[pflog] Hilo de PFlog finalizado.\n");
    return NULL;
}

void start_pflog_monitor(void) {
    if (thread_running) return;
    pthread_create(&pflog_thread_id, NULL, pflog_thread_routine, NULL);
    fprintf(stderr, "[pflog] Monitor PFlog iniciado.\n");
}

void stop_pflog_monitor(void) {
    if (!thread_running) return;
    if (pflog_handle) pcap_breakloop(pflog_handle);
    pthread_join(pflog_thread_id, NULL);
    fprintf(stderr, "[pflog] Monitor PFlog detenido.\n");
}

