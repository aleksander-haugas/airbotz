PREFIX?=/usr/local
CC?=cc
CFLAGS?=-O2 -pipe -std=c11 -Wall -Wextra -Wpedantic
CPPFLAGS+=-Iinclude -D_POSIX_C_SOURCE=200809L
LDFLAGS?=
SRC=src/main.c src/core.c src/config.c src/logger.c src/pf/pf.c src/ssh/ssh.c src/ssh/ssh_parser.c
OBJ=$(SRC:.c=.o)
all: airbotz
airbotz: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)
clean:
	rm -f $(OBJ) airbotz tests/test_ssh
test: airbotz
	$(CC) $(CPPFLAGS) $(CFLAGS) -o tests/test_ssh tests/test_ssh.c src/ssh/ssh_parser.c
	./tests/test_ssh
install: airbotz
	install -d $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/etc/airbotz $(DESTDIR)$(PREFIX)/etc/rc.d
	install -m 0555 airbotz $(DESTDIR)$(PREFIX)/sbin/airbotz
	install -m 0640 config/airbotz.conf $(DESTDIR)$(PREFIX)/etc/airbotz/airbotz.conf.sample
	install -m 0555 rc.d/airbotz $(DESTDIR)$(PREFIX)/etc/rc.d/airbotz
.PHONY: all clean test install
