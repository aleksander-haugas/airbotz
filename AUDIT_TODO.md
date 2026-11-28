# AirBotz Security Audit TODO

Branch: `rebuild/minimal-pf-ssh`

This checklist is the source of truth for the security/robustness audit. A task is closed only after its implementation (where applicable), automated tests, FreeBSD validation where applicable, and a commit have been verified.

Status legend: `[ ]` pending · `[~]` in progress · `[x]` verified and closed.

## Phase 1 — Storage and persistence

- [x] S1. Review and correct atomic replacement semantics in `src/storage.c`. FreeBSD 15.1 validation passed on commit `ee06c2c`: clean production build, full test suite, and root-only IPC integration test.
  - [x] S1.a Identify unchecked directory-open/fsync errors.
  - [x] S1.b Identify ambiguous failure after successful rename.
  - [x] S1.c Implement explicit result semantics: 0 = durable, -1 = not replaced, -2 = renamed but directory durability uncertain. Address Manager uses -3 for committed-but-uncertain and keeps PF/memory aligned. Commits: `044739b`, `b22f099`, `5c27940`, `690d8a3`; FreeBSD validation: `ee06c2c`.
  - [x] S1.d Expanded deterministic fault injection to write-stage, flush, file-fsync, file-close, rename, directory-fsync and directory-close paths. Pre-rename tests assert the prior file remains intact; post-rename tests assert the replacement is visible with an uncertain result. Full suite passed on FreeBSD 15.1, commit `ee06c2c`.
  - [x] S1.e Tests prove uncertain post-rename save does not roll PF back and memory follows visible storage. Startup restore completes reapplying live PF entries before returning the durability warning. Full suite passed on FreeBSD 15.1, commit `ee06c2c`. Commits: `5b9e5e9`, `640447e`, `c37410c`, `41f10cc`, `0e89f0e`, `76823a9`.
- [x] S2. Harden synchronization and error reporting for persistent files. Checked initialization `close()` and read `fclose()` results; cleanup preserves the original error; malformed data reports `EINVAL`; deterministic fault tests cover permanent/temporary read close failures and initialization close failure. Storage has no internal locks, but code review confirmed the daemon's current `core_run()` processes SSH, one IPC request, and expiry serially in a single event loop; this serialization requirement is documented in `include/storage.h`. FreeBSD 15.1 validation passed on `4f3e549`: clean production build, full `make test`, and root-only IPC integration test. Related commits: `025ae56`, `08e2460`, `99946c6`, `4f3e549`.
- [x] S3. Ensure consistency between storage, in-memory state, and PF on failure paths. FreeBSD 15.1 validation passed on commit `352dbf4`: clean production build, full `make test`, and root-only IPC integration test.
  - [x] S3.a Startup restore does not destructively roll back partially applied PF entries: without a PF membership snapshot, the manager cannot distinguish entries that predate startup from entries added during restore. It preserves the partial state and supports an idempotent retry. Deterministic test covers a pre-existing PF entry and a transient restore failure.
  - [x] S3.b Reviewed add/delete and expiry rollback paths. Clean rollback returns `-1`; failed compensating PF operations return `-2`; committed storage with uncertain directory durability returns `-3` while memory follows the visible file. Tests cover permanent/temporary add and delete, plus expiry rollback and rollback failure.
  - [x] S3.c Added deterministic tests for partial startup restore, expiry failure during PF deletion, expiry persistence failure, and failed compensation. Existing tests cover storage failures and rollback divergence for all four address operations. Full suite and root-only IPC test passed on FreeBSD 15.1 after commit `352dbf4`.
- [x] S4. Test malformed, truncated, oversized, and corrupted persistence files. Added strict record reading that rejects unterminated, overlong, NUL-containing, and malformed records; tests cover permanent and temporary lists, invalid IP data, invalid calendar expiry dates, and valid IPv4/IPv6 records. FreeBSD 15.1 validation passed on `b010d15`: clean production build, full `make test`, and root-only IPC integration test. Related commits: `27bc3da`, `4bfb651`, `b010d15`.
- [x] S5. Test recovery behavior after interrupted writes and process termination. Added test-only hard-exit points after the temporary file is synced/closed but before rename, and immediately after rename. Fork-based tests assert that pre-rename termination preserves the old destination and leaves an orphan temporary file, while post-rename termination exposes the replacement. Tests re-run `storage_init()` after each simulated crash to verify fresh-start loading. FreeBSD 15.1 validation passed on commit `2baf1f4`: `make clean`, production `make`, full `make test`, and root-only `sudo ./tests/test_ipc`. Orphan temporary files are harmless to list loading and are intentionally not automatically deleted pending a safe cleanup design. Related commits: `873aee4`, `d5ced36`, `ad28f87`, `f692742`, `2baf1f4`.

## Phase 2 — PF

- [x] P1. Review partial PF restoration failure paths. `address_manager_restore()` first removes expired temporary entries (with compensation on a failed delete or pre-commit persistence failure), then reapplies permanent and live temporary entries. A failure during reapplication can leave a partial PF restore; this is intentional because the manager has no table-membership snapshot and cannot distinguish pre-existing PF entries from entries added during this attempt. Retrying is safe/idempotent because PF table adds are idempotent. Tests cover a pre-existing PF member, a transient restore failure, and successful retry. Review completed against `src/address_manager.c`, `src/pf/pf.c`, and `tests/test_address_manager.c`.
- [~] P2. Design safe partial-restore reconciliation. Implemented bounded `pf_temp_snapshot()` / `pf_perm_snapshot()` wrappers around `pfctl -t <table> -T show`, plus a strict parser. Command output is capped at 256 KiB; parsing rejects unterminated, malformed, duplicate, NUL-containing, or over-capacity records and accepts validated IPv4/IPv6 entries. Parser tests cover empty output, IPv4/IPv6, CRLF, duplicates, invalid addresses, truncation, binary data, and insufficient capacity. FreeBSD 15.1 validation passed after commit `a2dfe63`: clean production build, full `make test`, root-only IPC integration, and live `make test-pf-live` / `sudo ./tests/test_pf_live`; both live snapshots returned zero entries and TEST-NET add/delete succeeded on both tables. Commits: `659c77c`, `6d7993b`, `74fe0bc`, `f57f10f`, `a2dfe63`. FreeBSD's `DIOCRSETADDRS` ioctl provides a single-operation table replacement, but it does not make a preceding snapshot plus replacement atomic against independent PF writers. Remaining safety limitation: a snapshot followed by separate add/delete commands is not atomic; while other PF writers may operate concurrently, it cannot prove ownership of an address that appears after the snapshot. Therefore do not automatically delete snapshot deltas until AirBotz can enforce exclusive table ownership or use an atomic PF transaction/ownership mechanism.
- [ ] P3. Complete reconciliation-specific failure/rollback tests and resulting diagnostics after P2 provides a safe ownership model. Existing `tests/test_address_manager.c` already covers PF mutation failures, failed compensating operations (`-2`), and persistence failures; do not add destructive reconciliation tests until exclusive table ownership or an atomic ownership mechanism is established.
- [x] P4. Report actual PF state in status rather than configuration intent. Added strict parsing of `pfctl -s info` status and live snapshot counts to the STATUS response; it distinguishes enabled, disabled, unavailable, and not-configured PF states and reports actual temporary/permanent PF table entry counts alongside persisted manager counts. Parser reference samples cover enabled/disabled, malformed and duplicate status lines. FreeBSD 15.1 validation passed: clean production build, full `make test`, root-only IPC test, live `make test-pf-live` / `sudo ./tests/test_pf_live`, and isolated end-to-end daemon/IPC STATUS test returned `OK running permanent=0 temporary=0 pf=enabled pf_temp_entries=0 pf_perm_entries=0`. The isolated daemon used a temporary config, SSH log, storage directory, and socket; production service was not restarted or modified.
- [x] P5. Harden pfctl execution and diagnostics. `waitpid()` retries `EINTR`; centralized logging covers fork/pipe/allocation/read/wait failures, non-zero child exit status, signal termination, and output-limit violations. Compile-time test-only executable-path and read-error hooks exercise non-zero exit, signal termination, exec failure (127), output-size rejection, simulated read failure, successful captured output, and diagnostic logging. Hooks are compiled only into `tests/test_pf`; production remains pinned to `/sbin/pfctl`. FreeBSD 15.1 validation passed: `make clean`, production `make`, full `make test`, direct `./tests/test_pf`, root-only `sudo ./tests/test_ipc`, and live PF tests all passed. Live PF tables remained clean. Commits: `d0d1366`, `4f7d88f`, `7ae985d`, `712a672`, `94e7a40`, `3953496`, `3b40f87`, `7699699`, `dd3ad6d`, `0aa855a`, `890a112`, `aaed6fd`, `51b73e8`, `bfa3b85`.

## Phase 3 — IPC

- [x] I1. Test incomplete IPC requests. Root integration tests cover a client that sends a partial request then half-closes and a client that connects but sends no data. Both are closed without invoking the request handler; client-side receive timeout bounds test duration. FreeBSD 15.1 validation passed: `make tests/test_ipc`, `sudo ./tests/test_ipc` (PASS), and full `make test` (all applicable tests passed; IPC correctly skips without root in the suite). Commits: `5134901`, `b5c049f`.
- [x] I2. Reject trailing data and malformed request framing. Server waits for client EOF after the single newline terminator and rejects embedded NUL, multiple frames, bytes after a terminator (including a later write), and over-limit frames. FreeBSD 15.1 validation passed: `make tests/test_ipc`, `sudo ./tests/test_ipc` (PASS), and full `make test` (all applicable tests passed; IPC correctly skips without root in the suite). Commits: `67b6bd4`, `6eacd0a`, `df0a7d3`.
- [x] I3. Test disconnects and simultaneous clients. Added integration coverage for abrupt disconnect after a partial request and four clients connected/queued concurrently; each must receive its own complete response without cross-talk. The server remains deliberately single-threaded and services queued clients sequentially. FreeBSD 15.1 validation passed: `make tests/test_ipc`, `sudo ./tests/test_ipc` (PASS), and full `make test` (all applicable tests passed; IPC correctly skips without root in the suite). Validation recorded after implementation commits `ccd13f6`, `d10b45a`, `d514909`.
- [~] I4. Verify request-size limits and timeouts. Added tests for the maximum accepted frame (254 payload bytes plus newline), oversized frames, and a slow client; IPC now enforces a 3-second absolute monotonic deadline for the complete request. FreeBSD 15.1 validation is currently failing: `sudo ./tests/test_ipc` reports `FAIL: idle IPC client was not timed out cleanly`; the unprivileged `make test` skips the root-only integration test and does not clear this failure. Diagnose and rerun the root integration test before closing. Commits: `acaf980`, `2fa4867`, `04e075f`.

## Phase 4 — SSHD detection engine (FreeBSD-first)

- [x] R0. Documented initial forensic references, event taxonomy, detection hypotheses, telemetry boundaries, parser gaps and engineering requirements. Documentation only; no parser behavior changed. Commit: `68138d7`.
- [x] R0.1. Expanded the research with the eight additional references, a FreeBSD-native capability matrix, realistic boundaries, Linux-only exclusions, host-integrity/session/network detection ideas, staged PF response, and an expanded implementation roadmap. WarnHack could not be retrieved reliably and remains explicitly unverified. Commit: `e60bea0`.
- [~] R1. Inventory and fingerprint the sample corpus. Confirmed local target: FreeBSD 15.1-RELEASE-p7 / OpenSSH 10.0p2; examined two downloaded corpora (4,100 and 2,000 sshd-matching lines). Source provenance, originating platform/version, time coverage and license/permission remain to be recorded. Do not assume downloaded samples match the local target.
- [~] R2. Catalogue exact sshd message shapes from samples. Initial catalogue records PAM unknown-user/authentication-failure variants, invalid-user preauth requests, authentication-limit disconnects, reverse-DNS mismatch warnings, SIGTERM and listener startup. Continue extracting exact variants and verify them against supported FreeBSD OpenSSH versions.
- [ ] R3. Define normalized event schema, timestamp semantics, session correlation keys and parser grammar.
- [ ] R4. Implement bounded syslog-envelope and sshd-message parsing; preserve unknown events safely.
- [ ] R5. Add reference-sample-driven tests for observed shapes, malformed/oversized/binary/partial records and false positives.
- [ ] R6. Implement bounded correlation windows for brute force, spraying-like behavior, enumeration, distributed activity and success-after-failure.
- [ ] R7. Implement connection-pattern detection using native socket/PF/packet metadata; measure cost and false positives.
- [ ] R8. Implement SSH host-integrity checks for sshd binary/config, authorized_keys, host keys and account metadata using trusted baselines.
- [ ] R9. Evaluate optional BSM/auditpipe integration on FreeBSD 15.1; verify kernel/config support and correlate events safely.
- [ ] R10. Evaluate optional session recording using native script(1)/supported sshd integration; document coverage, privacy, secret handling and impact. No automatic config edits.
- [ ] R11. Define explainable risk scoring, confidence/severity separation, baselines, allowlists and benign-sample tuning.
- [ ] R12. Implement staged PF response with AirBotz-owned tables, expiry, audit trail, operator override, safeguards and default-off policy.
- [ ] R13. Add status/telemetry/forensic reports and strict resource limits.
- [ ] R14. Validate on FreeBSD; run adversarial/fuzz/load tests; benchmark against Fail2ban/SSHGuard on identical datasets and publish precision, recall, latency and resource results.

## Phase 5 — SSH reader

- [ ] H1. Test excessively long and malformed SSH log lines, including partial records and bounded handling.
- [ ] H2. Review read errors and log-rotation recovery.

## Phase 5 — Configuration and daemon

- [ ] C1. Validate configuration values, duplicate keys, and invalid combinations.
- [ ] C2. Verify permissions and handling of sensitive paths.
- [ ] D1. Review signal handling and clean shutdown.
- [ ] D2. Test PID-file correctness and stale-socket recovery.

## Phase 6 — Final validation

- [ ] T1. Run the complete automated suite and regression tests on FreeBSD.
- [ ] T2. Complete final security review and update operational documentation.

## Safety constraints

- Do not modify `main`.
- Keep automatic SSH blocking disabled.
- Keep automatic service startup disabled until separately approved.
- Do not alter the user's active production configuration during audit work.
- Close checklist items only with recorded test evidence and a commit reference.


## Phase 7 — FreeBSD native service detection platform (project architecture)

- [x] F0. Define the FreeBSD-first product direction, modular architecture, dependency classes, service-parser roadmap, optional Nmap strategy and host-audit scope. Documentation baseline only; no runtime behavior changed. See `docs/AIRBOTZ_PROJECT_PLAN.md`.
- [ ] F1. Approve supported FreeBSD release matrix and verify base capabilities at build/runtime (libpcap, tcpdump, BSM/auditpipe, mtree, freebsd-update, service inventory).
- [ ] F2. Implement service discovery for installed/enabled/running services and actual listening sockets; distinguish base utilities from optional packages.
- [ ] F3. Define normalized event/evidence schema shared by all collectors and parsers.
- [ ] F4. Implement PF/libpcap network metadata collector and scan detection with bounded capture, filters, drop accounting and resource limits.
- [ ] F5. Evaluate Nmap as an optional external active-audit adapter. Require explicit target scope, authorization, rate limits, timeouts, XML parsing and an audit trail. Never make it a core daemon dependency.
- [ ] F6. Implement BSM/auditpipe collection after verifying kernel support, policy and event coverage.
- [ ] F7. Implement conditional service adapters: Samba/SMB, CUPS/IPP/printers, NFS/RPC, DNS, HTTP, SMTP, FTP/inetd, DHCP and SNMP.
- [ ] F8. Add cross-source correlation, explainable detections and capability/status reporting.
- [ ] F9. Add reference-sample-driven tests, malformed-input handling, adversarial/fuzz tests and FreeBSD validation for every module.

## Phase 8 — FreeBSD-native host security audit (rkhunter-inspired)

- [ ] A0. Design a read-only FreeBSD host audit engine; do not assume Linux paths, kernel interfaces or rkhunter checks are portable.
- [ ] A1. Define trusted-baseline creation, signing/storage, update lifecycle and remote/offline verification.
- [ ] A2. Audit base-system and critical-file integrity using mtree, SHA-256 and freebsd-update IDS where applicable.
- [ ] A3. Audit accounts, UID 0, groups, shells, authorized_keys and privilege configuration.
- [ ] A4. Audit startup/persistence: rc.conf, rc.d, loader.conf, cron, periodic and loaded kernel modules.
- [ ] A5. Audit processes, executable paths, listening sockets, setuid/setgid files and unusual writable executable locations.
- [ ] A6. Audit installed service configuration and exposure for SSHD, PF, Samba, CUPS, DNS, HTTP, mail, NFS and FTP when present.
- [ ] A7. Integrate pkg audit as an optional package-vulnerability check; do not install, upgrade or remove packages automatically.
- [ ] A8. Produce deterministic machine-readable reports with evidence, severity, confidence, skipped checks and remediation guidance.
- [ ] A9. Document rootkit-detection limitations: a compromised kernel or root account can tamper with local evidence; no local scanner can prove a host is clean.
- [ ] A10. Validate audit results against clean and intentionally modified FreeBSD test hosts; verify false positives and resource use.

## Phase 9 — Product quality and controlled response

- [ ] X1. Define per-module resource budgets, event-loss metrics and backpressure behavior.
- [ ] X2. Add safe report retention, redaction and optional remote evidence export.
- [ ] X3. Validate temporary/permanent PF response only after ownership, safeguards, allowlists and operator override are proven.
- [ ] X4. Benchmark against Fail2ban/SSHGuard and relevant audit tools using identical labeled datasets; publish precision, recall, false-positive rate, latency and resource use.
- [ ] X5. Complete threat model, secure defaults, upgrade/migration policy and release documentation.
