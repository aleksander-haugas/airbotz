PREFIX?=/usr/local
CC?=cc
CFLAGS+=-Iinclude -D_POSIX_C_SOURCE=200809L -std=c11 -Wall -Wextra -Wpedantic
LDFLAGS?=
SRC=src/main.c src/core.c src/config.c src/logger.c src/pf/pf.c src/ssh/ssh.c src/ssh/ssh_parser.c
OBJ=$(SRC:.c=.o)

all: airbotz

airbotz: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

tests/test_ssh: tests/test_ssh.c src/ssh/ssh_parser.c
	$(CC) $(CFLAGS) -o $@ tests/test_ssh.c src/ssh/ssh_parser.c

tests/test_pf: tests/test_pf.c src/pf/pf.c
	$(CC) $(CFLAGS) -o $@ tests/test_pf.c src/pf/pf.c

tests/test_pf_live: tests/test_pf_live.c src/pf/pf.c
	$(CC) $(CFLAGS) -o $@ tests/test_pf_live.c src/pf/pf.c

tests/test_ssh_rotation: tests/test_ssh_rotation.c src/ssh/ssh.c src/ssh/ssh_parser.c src/logger.c
	$(CC) $(CFLAGS) -o $@ tests/test_ssh_rotation.c src/ssh/ssh.c src/ssh/ssh_parser.c src/logger.c

clean:
	rm -f $(OBJ) airbotz tests/test_ssh tests/test_pf tests/test_pf_live tests/test_ssh_rotation

test: airbotz tests/test_ssh tests/test_pf tests/test_ssh_rotation
	./tests/test_ssh
	./tests/test_pf
	./tests/test_ssh_rotation

# Build this separately; execute with root privileges on a test FreeBSD host.
test-pf-live: tests/test_pf_live
	@echo "Run with root privileges: ./tests/test_pf_live"

install: airbotz
	install -d $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/etc/airbotz $(DESTDIR)$(PREFIX)/etc/rc.d
	install -m 0555 airbotz $(DESTDIR)$(PREFIX)/sbin/airbotz
	install -m 0640 config/airbotz.conf $(DESTDIR)$(PREFIX)/etc/airbotz/airbotz.conf.sample
	install -m 0555 rc.d/airbotz $(DESTDIR)$(PREFIX)/etc/rc.d/airbotz

.PHONY: all clean test test-pf-live install
