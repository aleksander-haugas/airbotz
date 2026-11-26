#include "logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
static FILE *out;
int logger_init(const char *path) {
    out=path ? fopen(path,"a") : stderr;
    return out ? 0 : -1;
}
void logger_log(const char *level,const char *fmt,...) {
    time_t now=time(NULL); struct tm tmv; char stamp[32]; va_list ap;
    if (!out) out=stderr;
    localtime_r(&now,&tmv); strftime(stamp,sizeof(stamp),"%Y-%m-%dT%H:%M:%S",&tmv);
    fprintf(out,"%s [%s] ",stamp,level?level:"INFO");
    va_start(ap,fmt); vfprintf(out,fmt,ap); va_end(ap);
    fputc('\n',out); fflush(out);
}
void logger_close(void) { if (out && out!=stderr) fclose(out); out=NULL; }
