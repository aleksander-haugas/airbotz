PREFIX?=/usr/local
CC?=cc
CFLAGS+=-Iinclude -D_POSIX_C_SOURCE=200809L -std=c11 -Wall -Wextra -Wpedantic
LDFLAGS?=
SRC=src/main.c src/core.c src/ipc.c src/config.c src/logger.c src/storage.c src/address_manager.c src/pf/pf.c src/ssh/ssh.c src/ssh/ssh_parser.c src/ssh/ssh_detection.c
OBJ=$(SRC:.c=.o)

all: airbotz

airbotz: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

tests/test_ssh: tests/test_ssh.c src/ssh/ssh_parser.c
	$(CC) $(CFLAGS) -o $@ tests/test_ssh.c src/ssh/ssh_parser.c

tests/test_pf: tests/test_pf.c src/pf/pf.c src/logger.c
	$(CC) $(CFLAGS) -DAIRBOTZ_PF_TESTING -o $@ tests/test_pf.c src/pf/pf.c src/logger.c

tests/test_pf_live: tests/test_pf_live.c src/pf/pf.c src/logger.c
	$(CC) $(CFLAGS) -o $@ tests/test_pf_live.c src/pf/pf.c src/logger.c

tests/test_ssh_rotation: tests/test_ssh_rotation.c src/ssh/ssh.c src/ssh/ssh_parser.c src/logger.c
	$(CC) $(CFLAGS) -DAIRBOTZ_SSH_TESTING -o $@ tests/test_ssh_rotation.c src/ssh/ssh.c src/ssh/ssh_parser.c src/logger.c

tests/test_ssh_detection: tests/test_ssh_detection.c src/ssh/ssh_detection.c src/logger.c
	$(CC) $(CFLAGS) -o $@ tests/test_ssh_detection.c src/ssh/ssh_detection.c src/logger.c

tests/bench_ssh_detection: tests/bench_ssh_detection.c src/ssh/ssh_detection.c src/logger.c
	$(CC) $(CFLAGS) -o $@ tests/bench_ssh_detection.c src/ssh/ssh_detection.c src/logger.c

bench-ssh-detection: tests/bench_ssh_detection
	./tests/bench_ssh_detection

tests/test_storage: tests/test_storage.c src/storage.c src/pf/pf.c src/logger.c
	$(CC) $(CFLAGS) -DAIRBOTZ_STORAGE_TESTING -o $@ tests/test_storage.c src/storage.c src/pf/pf.c src/logger.c

tests/test_address_manager: tests/test_address_manager.c src/address_manager.c src/storage.c src/pf/pf.c src/logger.c
	$(CC) $(CFLAGS) -DAIRBOTZ_STORAGE_TESTING -o $@ tests/test_address_manager.c src/address_manager.c src/storage.c src/pf/pf.c src/logger.c

tests/test_ipc: tests/test_ipc.c src/ipc.c
	$(CC) $(CFLAGS) -o $@ tests/test_ipc.c src/ipc.c

# Optional Clang/libFuzzer target; never part of the production build.
FUZZ_CC?=clang
FUZZ_CFLAGS?=-O1 -g -Iinclude -D_POSIX_C_SOURCE=200809L -std=c11 -Wall -Wextra -Wpedantic -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer

tests/fuzz_ssh_parser: tests/fuzz_ssh_parser.c src/ssh/ssh_parser.c include/ssh_parser.h
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ tests/fuzz_ssh_parser.c src/ssh/ssh_parser.c

# Copy immutable checked-in seeds to a disposable directory so libFuzzer
# cannot add generated corpus entries to the source tree.
fuzz-ssh: tests/fuzz_ssh_parser
	@set -eu; corpus=$$(mktemp -d /tmp/airbotz-fuzz.XXXXXX); \
	trap 'rm -rf "$$corpus"' EXIT; \
	cp tests/fuzz_ssh_corpus/* "$$corpus"/; \
	./tests/fuzz_ssh_parser -max_len=4096 -max_total_time=60 "$$corpus"

clean:
	rm -f $(OBJ) airbotz tests/test_ssh tests/test_pf tests/test_pf_live tests/test_ssh_rotation tests/test_ssh_detection tests/bench_ssh_detection tests/test_storage tests/test_address_manager tests/fuzz_ssh_parser

test: airbotz tests/test_ssh tests/test_pf tests/test_ssh_rotation tests/test_ssh_detection tests/test_storage tests/test_address_manager tests/test_ipc
	./tests/test_ssh
	./tests/test_pf
	./tests/test_ssh_rotation
	./tests/test_ssh_detection
	./tests/test_storage
	./tests/test_address_manager
	./tests/test_ipc

test-pf-live: tests/test_pf_live
	@echo "Run with root privileges: ./tests/test_pf_live"

.PHONY: all clean test test-pf-live fuzz-ssh bench-ssh-detection test_address_manager install

install: airbotz
	install -d $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/etc/airbotz $(DESTDIR)$(PREFIX)/etc/rc.d
	install -m 0555 airbotz $(DESTDIR)$(PREFIX)/sbin/airbotz
	install -m 0640 config/airbotz.conf $(DESTDIR)$(PREFIX)/etc/airbotz/airbotz.conf.sample
	install -m 0555 rc.d/airbotz $(DESTDIR)$(PREFIX)/etc/rc.d/airbotz
