# AirBotz Security Audit TODO

Branch: `rebuild/minimal-pf-ssh`

This checklist is the source of truth for the security/robustness audit. A task is closed only after its implementation (where applicable), automated tests, FreeBSD validation where applicable, and a commit have been verified.

Status legend: `[ ]` pending · `[~]` in progress · `[x]` verified and closed.

## Phase 1 — Storage and persistence

- [~] S1. Review and correct atomic replacement semantics in `src/storage.c`.
  - [x] S1.a Identify unchecked directory-open/fsync errors.
  - [x] S1.b Identify ambiguous failure after successful rename.
  - [ ] S1.c Define and implement explicit result semantics for pre-rename failure vs post-rename durability uncertainty.
  - [ ] S1.d Add deterministic fault-injection tests for write/flush/fsync/close/rename/directory-fsync paths.
  - [ ] S1.e Verify no incorrect PF rollback or memory/disk divergence on uncertain commit.
- [ ] S2. Harden synchronization and error reporting for persistent files.
- [ ] S3. Ensure consistency between storage, in-memory state, and PF on all failure paths.
- [ ] S4. Test malformed, truncated, oversized, and corrupted persistence files.
- [ ] S5. Test recovery behavior after interrupted writes and process termination.

## Phase 2 — PF

- [ ] P1. Review partial PF restoration failure paths.
- [ ] P2. Implement rollback for partially completed restoration.
- [ ] P3. Test rollback failures and resulting diagnostics.
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
