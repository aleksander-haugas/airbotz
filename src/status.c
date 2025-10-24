#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/rules.h"

#define ALERT_FILE "/var/log/airbotz_alerts.json"
#define MAX_LINE 8192
#define HASH_SIZE 1024   /* tamaño tabla hash (ajustable) */

/* ------------------ estructuras para eventos ------------------ */
typedef struct event_node {
    char *event;
    char service[32];
    long count;
    char last_ts[64];
    struct event_node *next;
} event_node;

static event_node *htable[HASH_SIZE];

/* djb2-ish hash */
static unsigned int str_hash(const char *s) {
    unsigned long h = 5381;
    while (*s) { h = ((h << 5) + h) + (unsigned char)(*s); s++; }
    return (unsigned int)(h & (HASH_SIZE - 1));
}

/* buscar o crear nodo */
static event_node *get_event_node(const char *service, const char *name) {
    unsigned int h = str_hash(name);
    event_node *e = htable[h];
    while (e) {
        if (strcmp(e->event, name) == 0 && strcmp(e->service, service) == 0) return e;
        e = e->next;
    }
    e = malloc(sizeof(event_node));
    if (!e) return NULL;
    e->event = strdup(name);
    strncpy(e->service, service, sizeof(e->service)-1);
    e->service[sizeof(e->service)-1] = '\0';
    e->count = 0;
    e->last_ts[0] = '\0';
    e->next = htable[h];
    htable[h] = e;
    return e;
}

/* liberar tabla */
static void free_table(void) {
    for (int i=0;i<HASH_SIZE;i++){
        event_node *e=htable[i];
        while(e){
            event_node *t=e->next;
            free(e->event);
            free(e);
            e=t;
        }
        htable[i]=NULL;
    }
}

/* parseo simplificado de línea JSON */
static void parse_alert_line(const char *line, char *service, size_t svc_sz,
                             char *event_out, size_t ev_sz, char *ts_out, size_t ts_sz) {
    service[0] = event_out[0] = ts_out[0] = '\0';
    const char *p;

    p = strstr(line, "\"service\":\"");
    if(p){ p+=11; const char *q=strchr(p,'\"'); if(q){ size_t l=q-p; if(l>=svc_sz)l=svc_sz-1; strncpy(service,p,l); service[l]='\0'; } }

    p = strstr(line, "\"event\":\"");
    if(p){ p+=9; const char *q=strchr(p,'\"'); if(q){ size_t l=q-p; if(l>=ev_sz)l=ev_sz-1; strncpy(event_out,p,l); event_out[l]='\0'; } }

    p = strstr(line, "\"timestamp\":\"");
    if(p){ p+=13; const char *q=strchr(p,'\"'); if(q){ size_t l=q-p; if(l>=ts_sz)l=ts_sz-1; strncpy(ts_out,p,l); ts_out[l]='\0'; } }
}

/* comparador descendente por count */
static int cmp_nodes_desc(const void *a,const void *b){
    const event_node * const *pa=a;
    const event_node * const *pb=b;
    if((*pb)->count>(*pa)->count) return 1;
    if((*pb)->count<(*pa)->count) return -1;
    return strcmp((*pa)->event,(*pb)->event);
}

/* helper para extraer IP desde JSON */
static void extract_ip(const char *line, char *ip_out, size_t sz) {
    ip_out[0] = '\0';
    const char *p = strstr(line, "\"ip\":\"");
    if (!p) return;
    p += 6;
    const char *q = strchr(p, '\"');
    if (!q) return;
    size_t l = q - p;
    if (l >= sz) l = sz - 1;
    strncpy(ip_out, p, l);
    ip_out[l] = '\0';
}

void show_status(void) {
    FILE *f=fopen(ALERT_FILE,"r");
    if(!f){ printf("No se encontraron alertas.\n"); return; }

    char line[MAX_LINE], service[32], ev[128], ts[64];
    long total_alerts=0;

    while(fgets(line,sizeof(line),f)){
        parse_alert_line(line, service, sizeof(service), ev, sizeof(ev), ts, sizeof(ts));
        if(ev[0]=='\0') continue;
        event_node *node=get_event_node(service,ev);
        if(!node) continue;
        node->count++;
        total_alerts++;
        if(ts[0] && (node->last_ts[0]=='\0' || strcmp(ts,node->last_ts)>0)){
            strncpy(node->last_ts,ts,sizeof(node->last_ts)-1);
            node->last_ts[sizeof(node->last_ts)-1]='\0';
        }
    }
    fclose(f);

    /* tabla de eventos */
    size_t slots=0;
    for(int i=0;i<HASH_SIZE;i++) for(event_node *e=htable[i];e;e=e->next) slots++;
    if(slots==0){ printf("No hay eventos.\n"); free_table(); return; }

    event_node **arr=malloc(sizeof(event_node*)*slots);
    if(!arr){ free_table(); return; }
    size_t idx=0;
    for(int i=0;i<HASH_SIZE;i++) for(event_node *e=htable[i];e;e=e->next) arr[idx++]=e;
    qsort(arr,slots,sizeof(event_node*),cmp_nodes_desc);

    printf("\n%-8s | %-25s | %-5s | %-7s | %-25s\n","Servicio","Evento","Count","% total","Último timestamp");
    printf("--------------------------------------------------------------------------\n");
    for(size_t i=0;i<slots;i++){
        double pct = total_alerts?((double)arr[i]->count*100.0/total_alerts):0.0;
        printf("%-8s | %-25s | %-5ld | %6.1f%% | %-25s\n",
               arr[i]->service,arr[i]->event,arr[i]->count,pct,arr[i]->last_ts[0]?arr[i]->last_ts:"-");
    }

    /* resumen por servicio */
    typedef struct { char name[32]; long total; } svc_sum;
    svc_sum services[32]; int svc_count=0;
    for(size_t i=0;i<slots;i++){
        int found=0;
        for(int j=0;j<svc_count;j++){
            if(strcmp(services[j].name,arr[i]->service)==0){ services[j].total+=arr[i]->count; found=1; break; }
        }
        if(!found){ strncpy(services[svc_count].name,arr[i]->service,sizeof(services[svc_count].name)-1);
            services[svc_count].total=arr[i]->count; svc_count++; }
    }

    /* ordenar y mostrar servicios */
    for(int i=0;i<svc_count-1;i++) for(int j=i+1;j<svc_count;j++)
        if(services[j].total>services[i].total){ svc_sum tmp=services[i]; services[i]=services[j]; services[j]=tmp; }

    printf("\n%-8s | %-12s | %-40s\n","Servicio","Total alerts","Trend");
    printf("--------------------------------------------------------------\n");
    for(int i=0;i<svc_count;i++){
        int bar_len = services[i].total*40/total_alerts;
        printf("%-8s | %-12ld | ",services[i].name,services[i].total);
        for(int b=0;b<bar_len;b++) putchar('#');
        for(int b=bar_len;b<40;b++) putchar(' ');
        printf("\n");
    }

    /* ----------------- Bans ----------------- */
    ActiveBan *bans=NULL; int ban_count=0;
    rules_get_active_bans(&bans,&ban_count);
    int temp_bans=0, perm_bans=0;
    for(int i=0;i<ban_count;i++){ if(bans[i].ban_expire==0) perm_bans++; else temp_bans++; }

    printf("\nTotal alerts: %ld\n",total_alerts);
    printf("Total IPs baneadas: %d\n",ban_count);
    printf("  - Temporales: %d\n",temp_bans);
    printf("  - Permanentes: %d\n\n",perm_bans);

    /* ----------------- Top agresores ----------------- */
#define MAX_SERVICES_PER_IP 64
    typedef struct { char svc[32]; long count; } svc_entry;
    typedef struct { char ip[64]; long total; char top_service[32]; } ip_info;

    ip_info ips_map[MAX_COUNTERS];
    svc_entry svc_map[MAX_COUNTERS][MAX_SERVICES_PER_IP];
    int svc_map_len[MAX_COUNTERS];
    int ips_len = 0;

    FILE *fa = fopen(ALERT_FILE, "r");
    if (fa) {
        char lbuf[MAX_LINE];
        while (fgets(lbuf, sizeof(lbuf), fa)) {
            char svc[32] = "";
            char evtmp[128], ttmp[64], ip[64] = "";
            parse_alert_line(lbuf, svc, sizeof(svc), evtmp, sizeof(evtmp), ttmp, sizeof(ttmp));
            extract_ip(lbuf, ip, sizeof(ip));
            if (ip[0] == '\0' || svc[0] == '\0') continue;

            int idx = -1;
            for (int i = 0; i < ips_len; i++) {
                if (strcmp(ips_map[i].ip, ip) == 0) { idx = i; break; }
            }
            if (idx == -1) {
                if (ips_len >= MAX_COUNTERS) continue;
                idx = ips_len++;
                memset(&svc_map[idx][0], 0, sizeof(svc_map[idx]));
                svc_map_len[idx] = 0;
                strncpy(ips_map[idx].ip, ip, sizeof(ips_map[idx].ip)-1);
                ips_map[idx].total = 0;
                ips_map[idx].top_service[0] = '\0';
            }
            ips_map[idx].total++;

            int si = -1;
            for (int s = 0; s < svc_map_len[idx]; s++) {
                if (strcmp(svc_map[idx][s].svc, svc) == 0) { si = s; break; }
            }
            if (si == -1) {
                if (svc_map_len[idx] < MAX_SERVICES_PER_IP) {
                    si = svc_map_len[idx]++;
                    strncpy(svc_map[idx][si].svc, svc, sizeof(svc_map[idx][si].svc)-1);
                    svc_map[idx][si].count = 1;
                }
            } else {
                svc_map[idx][si].count++;
            }
        }
        fclose(fa);
    }

    for (int i = 0; i < ips_len; i++) {
        long topc = 0;
        ips_map[i].top_service[0] = '\0';
        for (int s = 0; s < svc_map_len[i]; s++) {
            if (svc_map[i][s].count > topc) {
                topc = svc_map[i][s].count;
strncpy(ips_map[i].top_service, svc_map[i][s].svc, sizeof(ips_map[i].top_service)-1);                
            }
        }
        if (ips_map[i].top_service[0] == '\0')
            strncpy(ips_map[i].top_service, "-", sizeof(ips_map[i].top_service)-1);
    }

    for (int i = 0; i < ips_len - 1; i++) {
        for (int j = i + 1; j < ips_len; j++) {
            if (ips_map[j].total > ips_map[i].total) {
                ip_info tmp = ips_map[i];
                ips_map[i] = ips_map[j];
                ips_map[j] = tmp;
            }
        }
    }

    printf("Top agresores:\n");
    printf("%-15s | %-7s | %-30s\n", "IP", "Alertas", "Servicio más atacado");
    printf("---------------------------------------------------------------\n");
    for (int i = 0; i < ips_len && i < 10; i++) {
        printf("%-15s | %-7ld | %-30s\n", ips_map[i].ip, ips_map[i].total, ips_map[i].top_service);
    }

    free(arr);
    free_table();
}

