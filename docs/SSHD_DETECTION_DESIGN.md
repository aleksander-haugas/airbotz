# SSHD Detection Design — FreeBSD-first

Status: source/account brute force, source password spraying, source-address canonicalization, and bounded distributed brute force (one account across multiple source IPs) are validated on FreeBSD 15.1. Distributed spraying and other correlation families remain design work.

This document defines the safety and data semantics required before AirBotz turns parsed SSHD records into detections. It does not enable PF actions, change the production configuration, or claim that the current parser is a complete OpenSSH grammar.

## 1. Current implementation boundary

The current branch has:
- a bounded, length-aware syslog/SSHD parser with explicit unknown events;
- normalized event types for authentication, PAM, disconnects, sessions, transport/protocol errors and selected operational messages;
- a production log tailer with partial-line handling, oversized-record discard, rename rotation and copytruncate recovery;
- dispatch into the core, which writes normalized SSH event summaries and invokes observe-only source/account brute-force and source password-spray detectors.

The core includes bounded SSH detections for repeated failures against one account from one source, low-rate failures spread across multiple accounts from one source, and repeated failures against one account spread across multiple source IPs. Unknown events are still ignored by the SSH callback. Distributed password spraying across multiple accounts and source IPs, invalid-account enumeration, success-after-failure, risk scoring and richer alert reporting are not implemented. No SSH-triggered PF response exists.

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


## 11. Initial implementation — source/account brute force and password spraying

Both rules are deliberately bounded and observe-only. They use only normalized `SSH_EVENT_FAILED_PASSWORD` records with a valid parsed IPv4/IPv6 source address. PAM failures, invalid-user diagnostics, disconnects and transport errors are not counted as separate authentication attempts.

### 11.1 Source/account brute force

- Counts failed-password observations from the same canonical source address against the same non-empty parsed username. The account label in the finding is sanitized before logging because usernames originate from untrusted remote input.
- Initial threshold: 8 observations in a 300-second monotonic window. These are provisional engineering values, not thresholds inferred from reference samples.
- Emits once when the source/account count crosses the threshold; a later crossing can occur after the old observations expire.
- Records without a parsed username are excluded from both account-specific brute-force and password-spray correlation.

### 11.2 Source password spraying

- Counts failures from one canonical source across distinct non-empty usernames in the same 300-second monotonic window.
- Provisional trigger: at least 8 failed-password observations, at least 5 distinct accounts, and no more than 2 observations against any one account.
- This is intentionally a separate pattern from repeated attempts against one account. It does not detect distributed spraying across multiple source addresses.
- A finding is emitted only when all three conditions become true; it is not repeated for every subsequent failure while the condition remains true.

### 11.3 Distributed brute force against one account

- Aggregates failed-password observations for one parsed username across canonical source IP addresses.
- Provisional trigger: at least 8 observations, at least 5 distinct source IPs, and no more than 2 observations from any one source within the 300-second monotonic window.
- Emits once when the combined pattern crosses all conditions. A single source repeatedly attacking one account does not satisfy this rule.
- The rule is a heuristic, not proof of coordination: shared NAT, proxy infrastructure, botnets and legitimate distributed clients can produce overlapping patterns. Findings remain observe-only and provisional.
- Distributed password spraying (multiple accounts attacked across multiple IPs) is a different pattern and is not implemented by this rule.

### 11.4 Shared evidence and limits

- A syslog repetition summary contributes its explicit number of additional copies, not one plus that number. The summary remains one bounded observation and does not synthesize timestamps. The represented copies have reduced temporal precision.
- The correlation store is a fixed 4096-entry ring. It expires entries by monotonic time and reports capacity evictions and partial visibility. The pre-event detection state is evaluated after any required eviction, so an evicted observation cannot incorrectly suppress a threshold crossing.
- Source keys are canonicalized with `inet_pton()` / `inet_ntop()`. Equivalent IPv4/IPv6 textual forms share a key. Invalid or unterminated address fields are rejected. IPv4-mapped IPv6 addresses remain in the IPv6 family and are not merged with native IPv4 addresses.
- Per-account spray counts use a fixed-size hash table bounded above the maximum ring occupancy; scratch memory and correlation state are bounded.
- STATUS exposes failed-password observation count, local brute-force findings, source password-spray findings, distributed brute-force findings, active ring entries, capacity evictions and partial-visibility state.
- Capacity eviction reduces finding confidence because older evidence may have been lost. The detector never infers an account from adjacent log records.
- Thresholds require tuning against labelled benign and attack datasets. No inference should be drawn from the frequency of messages in a small reference corpus.
- No PF command, address-manager mutation, service change or automatic block is invoked.

Distributed brute force against one account is implemented and validated on FreeBSD 15.1. Operator validation after the distributed-rule implementation: `make clean`, warning-free production `make`, `make test`, and `sudo make test` all passed; the latter included root-only IPC. The `test_ssh_detection` regression explicitly passed the local/distributed brute-force and source password-spray correlation scenarios, including windows, thresholds, expiry, repetition summaries and capacity telemetry. This validates the tested implementation and scenarios, not threshold suitability for every deployment. Distributed password spraying across multiple accounts and source IPs, invalid-account enumeration, success-after-failure and risk scoring remain future work.