#include "core.h"
#include <stdio.h>
int main(int argc,char **argv) {
    const char *config="config/airbotz.conf";
    if (argc==3 && argv[1][0]=='-' && argv[1][1]=='c') config=argv[2];
    else if (argc!=1) { fprintf(stderr,"Usage: %s [-c config]\n",argv[0]); return 2; }
    if (core_init(config)!=0) { fprintf(stderr,"AirBotz initialization failed\n"); return 1; }
    core_run(); core_shutdown(); return 0;
}
