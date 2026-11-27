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
- [ ] P2. Design safe partial-restore reconciliation. Add a reliable PF table-membership snapshot (or equivalent ownership tracking) before considering rollback; never blindly delete entries after a partial restore because some may predate AirBotz.
- [ ] P3. Test reconciliation/rollback failures and resulting diagnostics once P2 provides a safe ownership model.
- [ ] P4. Report actual PF state in status rather than configuration intent.
- [ ] P5. Harden pfctl execution, including waitpid EINTR handling and diagnostics.

## Phase 3 — IPC

- [ ] I1. Test incomplete IPC requests.
- [ ] I2. Reject trailing data and malformed request framing.
- [ ] I3. Test disconnects and simultaneous clients.
- [ ] I4. Verify request-size limits and timeouts.

## Phase 4 — SSH reader

- [ ] H1. Test excessively long and malformed SSH log lines.
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
