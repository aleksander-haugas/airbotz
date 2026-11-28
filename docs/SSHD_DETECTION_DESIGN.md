# SSHD Detection Design — FreeBSD-first

Status: design baseline; implementation and operator validation pending.

This document defines the safety and data semantics required before AirBotz turns parsed SSHD records into detections. It does not enable PF actions, change the production configuration, or claim that the current parser is a complete OpenSSH grammar.

## 1. Current implementation boundary

The current branch has:
- a bounded, length-aware syslog/SSHD parser with explicit unknown events;
- normalized event types for authentication, PAM, disconnects, sessions, transport/protocol errors and selected operational messages;
- a production log tailer with partial-line handling, oversized-record discard, rename rotation and copytruncate recovery;
- dispatch into the core, which currently writes normalized SSH event summaries to the AirBotz log.

The current core is an event logger, not yet an SSHD detection engine. Unknown events are currently ignored by the SSH callback. No SSH correlation, risk score, alert report or SSH-triggered PF response exists.

The reader opens the configured log at EOF on daemon startup. It intentionally does not replay historical records. A deleted/missing path after startup is currently retried by the reader, but SSH source health and event-loss telemetry are not exposed as a complete status contract.

## 2. Event semantics and evidence quality

Parsing must describe what the record says, not decide whether it is malicious.

- Failed password, Failed none, PAM authentication failure, PAM check-pass, PAM failure summary and PAM max-retries are distinct record types. One authentication interaction can emit several of them.
- Invalid user and input_userauth_request: invalid user may refer to the same underlying interaction. Do not count them as separate attempts without corroborating connection evidence.
- Received disconnect is client-originated; Disconnecting is server-originated. Preserve this direction.
- Connection closed / Disconnected from are lifecycle observations, not authentication failures.
- Accepted authentication is success, but does not by itself prove a privileged action or a fully established interactive session.
- session opened / session closed are account lifecycle records. They may be unmatched, delayed, or emitted by PAM; adjacency is not a valid pairing rule.
- Reverse-DNS mismatch, bad protocol identification, bad packet length and corrupted MAC are contextual protocol/network evidence, not standalone proof of malicious intent.
- error / fatal severity remains independent from event family and attack confidence.
- [preauth] explicitly establishes a pre-authentication marker. Its absence must remain unknown, not be interpreted as post-authentication.
- Syslog message-repeated summaries represent additional copies observed by syslog compression. The summary timestamp is not the timestamp of every represented copy. Never synthesize per-copy timestamps or double-count the ordinary record that may precede the summary.

Every normalized field must carry availability/quality semantics. Missing IP, username, port, PID or timestamp must remain missing; never infer one from a neighboring line.

## 3. Time model for correlation

The existing RFC3164-style timestamp has month/day/time but no year or timezone. It cannot safely be used as a globally ordered timestamp across year boundaries, clock corrections or hosts.

Before implementing windows, add two separate times:
1. event_time: parsed source timestamp with explicit quality (yearless_local, absolute, or unknown). Do not silently attach a year or timezone.
2. observed_time: collector wall-clock time when AirBotz reads the complete record, plus a monotonic clock value for in-process window expiry.

Use monotonic time for live correlation-window expiry. Use observed wall time for operator-facing reports and event_time only as source evidence. Mark delayed records and rotation/replay explicitly if later supported.

A repetition summary contributes a bounded represented-count observation at its observed time, with reduced temporal precision. It must not be expanded into fabricated events.

## 4. Correlation dimensions

Use independent, explainable dimensions rather than one opaque score:

- source address: failures, distinct target accounts, methods and connection fan-out;
- target account: failures across sources, invalid-user status and later success;
- source + target account: repeated attempts against one account;
- connection evidence: source address + source port + sshd PID + bounded time window, where fields are present and trustworthy;
- process/session evidence: PID + username + event order + time, while accounting for PID reuse and unmatched PAM lifecycle events;
- host/service: hostname, configured log source and sshd process context.

Source port and PID are supporting keys, not universal identifiers. NAT, proxies, reused ports, multiple sshd workers and missing fields can make a connection key incomplete. A correlation result must expose which keys were actually available.

Do not join events solely because they are adjacent in the log or share a username.

## 5. Initial detection hypotheses

Implement and report these as separate hypotheses, not a single generic attack label:

1. Repeated authentication failures from one source — count distinct authentication interactions, not raw lines.
2. Spraying-like source behavior — one source targets many distinct accounts in a window. This is a hypothesis, not proof of password reuse.
3. Distributed account targeting — one account receives failures from many distinct sources in a window.
4. Invalid-account enumeration — distinct invalid account names and source diversity, separated from ordinary failed authentication.
5. Success after failures — successful authentication following failures, scoped by source/account and window; report sequence evidence without claiming compromise.
6. Protocol/connection anomaly — repeated bad identification, malformed packet, MAC or transport failures. Keep separate from authentication abuse.
7. Privileged-account access — successful authentication/session for sensitive accounts, correlated with account policy and trusted administration sources. Do not treat root alone as proof of malicious activity.
8. Session lifecycle inconsistency — unmatched open/close observations or unusual duration only when trustworthy timestamps and pairing evidence exist.

Thresholds must not be copied from the sample corpus. They require labelled benign and malicious datasets, environment-specific configuration, allowlists and false-positive evaluation.

## 6. Bounded state and resource safety

The correlation engine must have explicit limits for:
- total active source/account/connection keys;
- per-key counters and distinct-account/source cardinality;
- event age and window duration;
- memory use and eviction policy;
- maximum alerts per interval and report size;
- input queue/backpressure and behavior when limits are reached.

Eviction and saturation must be observable. On capacity exhaustion, AirBotz must degrade to a documented partial-visibility state, not silently allocate without bound or claim complete detection. Hash-table design must resist attacker-controlled high-cardinality keys.

No raw untrusted message text should be interpolated into line-oriented logs without escaping. Keep sanitized evidence excerpts bounded and optional; protect secrets and privacy.

## 7. Finding contract

A finding should include:
- stable rule ID and rule version;
- hypothesis/category and concise explanation;
- source/account/host dimensions actually observed;
- first/last observed time and window quality;
- raw event count and deduplicated interaction count separately;
- supporting event references and missing-evidence flags;
- severity and confidence as separate values;
- threshold/baseline used and allowlist match, if any;
- state-capacity or source-health warnings;
- recommended operator action.

A parser event is not a finding. Severity from OpenSSH is not AirBotz confidence. Confidence must reflect evidence quality and correlation strength.

## 8. Response boundary

Initial SSHD release is observe-and-report only:
- no automatic PF additions;
- no automatic changes to sshd_config, firewall rules or accounts;
- no service restart or configuration rewrite;
- alerts and recommendations only.

A later response stage must require explicit policy, dry-run preview, allowlists for management/trusted addresses, protected recovery paths, AirBotz-owned PF tables, expiry, audit trail, operator override and rollback tests. It must remain default-off.

## 9. Required validation before SSHD detection is production-usable

1. Finish corpus inventory with provenance, platform/version, year/timezone and permission documented where available. Raw user logs remain local; only synthetic/sanitized samples may enter Git.
2. Measure unknown/unclassified and malformed records by message family, without publishing raw sensitive log lines.
3. Add positive and negative parser cases from supported FreeBSD/OpenSSH versions.
4. Add collector health: source missing/reappeared, rotation, truncation, read errors, discarded oversized records, last-read time and event counters.
5. Implement the time model and bounded correlation state.
6. Build labelled benign/malicious test scenarios and assert exact deduplicated counts and finding explanations.
7. Tune thresholds against the target environment; measure precision, recall, false-positive rate, latency, CPU, memory, I/O and event loss.
8. Test restart, log rotation, clock jumps, year boundary, delayed records, syslog repeat summaries, high-cardinality attacks and state exhaustion.
9. Validate on the supported FreeBSD/OpenSSH release matrix and document exact telemetry coverage.
10. Release first in monitor-only mode. PF response is a separate, later approval gate.

## 10. Explicit non-goals and limits

- Passive SSH log parsing cannot reveal encrypted command contents.
- A log record is not a guaranteed unique TCP connection or authentication attempt.
- A local root/kernel compromise can tamper with local logs and AirBotz evidence.
- No parser can classify every message from every OpenSSH build without versioned samples and ongoing regression coverage.
- Benchmark claims against Fail2ban/SSHGuard require identical labelled datasets and published methodology; do not claim superiority before that work.


## 11. Initial implementation — source brute-force rule

The first R6 implementation is deliberately narrow and observe-only:

- Only normalized `SSH_EVENT_FAILED_PASSWORD` records with a valid parsed IPv4/IPv6 source address contribute to the source brute-force rule.
- PAM failure records, invalid-user diagnostic records, disconnects and transport errors are not counted as separate authentication attempts. This avoids inflating one authentication interaction with adjacent log messages.
- The initial conservative baseline is 8 failed-password observations from one source within a 300-second monotonic window. These are engineering starting values, not thresholds inferred from the reference samples; later tuning must use labelled benign and attack datasets.
- A syslog repetition summary contributes its explicit number of additional copies, not one plus that number. The summary remains one bounded observation and does not synthesize timestamps. The represented copies have reduced temporal precision because the summary does not carry timestamps for each copy.
- The correlation store is a fixed 4096-entry ring. It expires entries by monotonic time and reports capacity evictions and a partial-visibility flag. A capacity eviction reduces finding confidence because older evidence may have been lost.
- Source keys are exact parsed IP address strings in this first cut; later normalization may canonicalize alternate textual representations of the same IPv6 address.
- A finding is emitted once when the source count crosses the threshold, not on every subsequent failure while above threshold.
- STATUS exposes observed failure-record count, finding count, active ring entries, capacity evictions and partial-visibility state.
- No PF command, address-manager mutation, service change or automatic block is invoked.

This first rule does not yet detect password spraying, distributed targeting, invalid-account enumeration or success-after-failure. Those require separate state dimensions and evidence semantics and remain subsequent R6 work.
