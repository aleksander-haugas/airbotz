#include "ssh.h"
#include "logger.h"
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#define LINE_MAX_AB 4096
int ssh_extract_address(const char *,char *,size_t);
const char *ssh_classify(const char *);
static FILE *logf;
static char log_path[512];
int ssh_init(const char *path) {
    struct stat st;
    if (!path || strlen(path)>=sizeof(log_path)) return -1;
    strcpy(log_path,path);
    logf=fopen(path,"r");
    if (!logf) return -1;
    if (fstat(fileno(logf),&st)==0) fseek(logf,0,SEEK_END);
    return 0;
}
void ssh_process(void) {
    char line[LINE_MAX_AB],ip[INET6_ADDRSTRLEN];
    if (!logf) return;
    while (fgets(line,sizeof(line),logf)) {
        const char *kind=ssh_classify(line);
        if (strcmp(kind,"other")) {
            if (ssh_extract_address(line,ip,sizeof(ip)))
                logger_log("SSH","%s from %s",kind,ip);
            else logger_log("SSH","%s (address unavailable)",kind);
        }
    }
    if (ferror(logf)) { clearerr(logf); logger_log("WARN","SSH log read error"); }
}
void ssh_shutdown(void) { if (logf) fclose(logf); logf=NULL; }
