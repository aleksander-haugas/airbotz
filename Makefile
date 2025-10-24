PROG=airbotz
SRCS=src/main.c src/parser_pflog.c src/state_manager.c src/parser_sshd.c src/parser_nginx.c src/parser_vsftpd.c src/status.c src/rules.c src/actions.c
CFLAGS+=-Iinclude -Wall -Wextra -O2 -pipe
PREFIX?=/usr/local
BINDIR=${PREFIX}/sbin

# --- Airbotz system integration variables ---
# Grupo requerido para leer el dispositivo /dev/pflog0 (BPF)
SYS_GROUP?=bpf
PFTABLES_DIR=/etc/pf.tables
CONF_PATH=${PREFIX}/etc/airbotz.conf

all: ${PROG}

${PROG}: ${SRCS}
	${CC} ${CFLAGS} ${SRCS} -o ${PROG} -lpcap -pthread

install:
	# Instalar el binario en sbin
	install -d ${DESTDIR}${BINDIR}
	# CRÍTICO: Establece el grupo a 'bpf' para permitir la lectura de pflog0 (incluso con SecureLevel 3)
	install -m 555 -g ${SYS_GROUP} ${PROG} ${DESTDIR}${BINDIR}/${PROG}
	
	# Instalar script de servicio (rc.d)
	install -d ${DESTDIR}/usr/local/etc/rc.d
	install -m 555 rc.d/airbotz ${DESTDIR}/usr/local/etc/rc.d/airbotz
	
	# Instalar archivo de configuración
	install -d ${DESTDIR}${PREFIX}/etc
	install -m 644 airbotz.conf ${DESTDIR}${CONF_PATH}
	
	# Crear el directorio requerido por las tablas de PF
	install -d ${DESTDIR}${PFTABLES_DIR}

deinstall:
	rm -f ${DESTDIR}${BINDIR}/${PROG}
	rm -f ${DESTDIR}/usr/local/etc/rc.d/airbotz
	rm -f ${DESTDIR}${CONF_PATH}
	# Nota: No se elimina ${PFTABLES_DIR} ya que puede contener datos de otros servicios.

clean:
	rm -f ${PROG} *.o src/*.o

