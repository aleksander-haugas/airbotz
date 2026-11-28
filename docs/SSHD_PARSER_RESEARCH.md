# SSHD Parser Research and Detection Engineering Log

Status: research baseline documented; implementation work intentionally paused pending sample corpus review.
Scope: OpenSSH/sshd authentication and connection logs consumed by AirBotz on FreeBSD. This document is the working source of truth for parser research, evidence, hypotheses, tests, and implementation decisions.

## 1. Objectives

Build a robust, conservative SSH telemetry parser that:

- Parses real OpenSSH/sshd records across supported message variants and operating-system logging formats.
- Extracts structured fields without assuming fixed whitespace positions: timestamp, host, process/program, PID, event type, username, source address, source port, authentication method, protocol, session identifiers, and relevant reason/status fields when present.
- Distinguishes authentication outcomes, invalid-user probes, connection lifecycle, protocol negotiation, disconnects, and post-authentication/session evidence.
- Correlates events over time and across process/session/source dimensions to identify brute force, password spraying, username enumeration, distributed attempts, opportunistic scanning, and suspicious successful access.
- Produces explainable detections with evidence, confidence, time window, and supporting event counts. It must not claim certainty where logs only support a hypothesis.
- Keeps parsing, detection, policy, and enforcement separate. No automatic SSH blocking is enabled by this research.

## 2. Research references reviewed

### 2.1 Fl1x — SSHD Logs Parse Forensics

URL: https://fl1xh.github.io/posts/sshd_parse_forensics/

Useful observations:
- Authentication logs are mixed service logs; identify the sshd/PAM event source rather than treating every auth.log line as SSH.
- Extract successful and failed authentication, invalid usernames, and source addresses.
- Aggregate distinct usernames and source IPs instead of relying only on individual lines.
- Connection disconnect messages can be useful reconnaissance signals.

Limitations and AirBotz interpretation:
- The article is an introductory manual workflow, not a formal OpenSSH grammar or a complete scanner detector.
- Fixed awk field positions are fragile across message variants and IPv6.
- A "Received disconnect" event alone does not prove port scanning. Legitimate clients, health checks, interrupted sessions, and scanners can all disconnect. Treat it as a connection-lifecycle observation and correlate it with timing, authentication progress, volume, and other evidence.
- AirBotz should parse fields structurally and avoid treating a single disconnect as a malicious verdict.

### 2.2 kamer-heap — SSH Log Forensics

URL: https://github.com/kamer-heap/ssh-log-forensics/

Useful observations:
- Preserve evidence and build a chronological timeline before drawing conclusions.
- Compare pre-incident and post-incident baselines.
- Correlate repeated failures, a later successful authentication, session-open records, and subsequent system activity.
- Treat persistence and post-compromise claims as hypotheses unless corroborated by additional artifacts.

Limitations and AirBotz interpretation:
- The repository describes a specific Linux incident; its IPs, usernames, commands, and sequence are case data, not universal signatures.
- A successful login after failures is high-value context, but not proof of compromise by itself.
- Authentication logs alone do not establish which commands were run or whether persistence was installed.

### 2.3 Security Arsenal — TTY Log Forensics

URL: https://securityarsenal.com/blog/tty-log-forensics-turning-honeypot-attacker-keystrokes-into-production-ssh-defense

Useful observations:
- Post-authentication behavior can reveal intent that is invisible in ordinary authentication logs.
- Common investigative stages include host/environment reconnaissance, payload retrieval, execution, cleanup, persistence, and lateral movement preparation.
- TTY/session telemetry becomes substantially more useful when correlated with authentication identity, source address, and session time.

Critical telemetry boundary:
- TTY keystrokes, shell commands, process execution, and terminal output are NOT normally present in sshd auth.log.
- These detections require a separately configured and supported telemetry source (session recording, audit subsystem, process accounting, eBPF, or a compatible FreeBSD mechanism). AirBotz must not pretend to infer commands from authentication events.
- The article's concrete collection mechanisms are Linux-oriented. Any FreeBSD implementation needs a separate feasibility, privacy, performance, and operational review.
- Post-login command patterns belong in a future session-telemetry module, not in the current auth.log parser.

### 2.4 Noel-BijuJohn — HTB Brutus SSH Forensics

URL: https://github.com/Noel-BijuJohn/htb-brutus-ssh-forensics

Useful observations:
- Frequency analysis can identify dominant brute-force sources.
- Timing can help distinguish automated bursts from longer interactive sessions.
- Correlating authentication logs with login accounting artifacts (for example Linux wtmp) improves timeline reconstruction.
- Detection engineering can map multi-stage activity to MITRE ATT&CK and produce rules for SIEM consumers.

Limitations and AirBotz interpretation:
- This is a lab/simulation case study, not a representative universal dataset.
- IP frequency alone misses distributed password spraying and can overstate NAT/shared-source activity.
- Linux wtmp parsing is not directly portable to FreeBSD. FreeBSD login accounting and available audit records require their own format-specific handling.
- A root login or a new account event should be interpreted in host policy and baseline context, not automatically declared malicious.

## 3. Initial event taxonomy

The parser should normalize raw messages into stable event categories. The exact taxonomy will be refined against the supplied corpus.

| Family | Candidate events / evidence |
|---|---|
| Authentication failure | Failed password, failed public-key/authentication, PAM authentication failure |
| Invalid identity | Invalid user, unknown user, user not allowed, account policy rejection |
| Authentication success | Accepted password, Accepted publickey, Accepted keyboard-interactive, other accepted methods |
| Connection lifecycle | Connection from, connection closed, disconnected, Received disconnect, reset/timeout |
| Pre-authentication abuse | MaxStartups/drop, repeated unauthenticated connections, protocol/banner anomalies |
| Negotiation | KEX, cipher/MAC/host-key negotiation failures or incompatibility where logged |
| Session lifecycle | session opened/closed, subsystem request, shell/command/PTY evidence where available |
| Operational/security context | sshd start/reload, configuration/key errors, PAM/account restrictions |

Do not assume every OpenSSH version or syslog configuration emits every family. Unknown messages must remain safely classifiable as unknown/other and must not crash or poison parser state.

## 4. Detection hypotheses (not yet implementation rules)

All detections must be based on a bounded time window, normalized source identity, event counts, and explainable evidence. Thresholds will be calibrated using the supplied samples and benign baselines; no universal threshold is committed here.

1. **Brute force:** many failed authentication attempts from one source, potentially across one or several usernames, in a short window.
2. **Password spraying:** one or a small set of passwords cannot be inferred from standard sshd logs; operationally, detect a source attempting many distinct usernames with low attempts per username. Label this as spraying-like behavior, not proof of password reuse.
3. **Username enumeration:** repeated invalid/nonexistent usernames or account-policy probes, with source and time correlation.
4. **Distributed brute force:** similar username targeting or failure bursts from multiple source addresses. Avoid merging unrelated events solely because usernames match.
5. **Success after attack activity:** successful authentication following failures from the same source/account or correlated campaign. Raise priority, but do not label compromise without more evidence.
6. **Root/direct privileged access:** successful privileged-account access, scored against local policy and baseline; legitimate administration remains possible.
7. **Connection scanning/probing:** repeated short-lived connections, disconnect-before-authentication, protocol/banner anomalies, or high connection rates. A single disconnect is insufficient.
8. **Authentication method anomalies:** unexpected method changes, repeated negotiation/authentication failures, or success using a method disallowed by expected policy when that policy is available.
9. **Session anomalies:** unusual session timing, rapid open/close loops, or multiple sessions from a source/account; require careful baseline and session correlation.
10. **Post-authentication intrusion chain:** reconnaissance, download-and-execute, persistence, cleanup, and lateral movement indicators. This is out of scope for auth.log-only parsing and requires independent command/process/TTY telemetry.

## 5. Predictive / behavioral scoring principles

AirBotz may estimate that an ongoing sequence resembles a known attack pattern, but it must not claim to predict an attacker's future actions with certainty.

- Start with deterministic event facts and transparent aggregation.
- Use sequence context: e.g. connection -> invalid user -> repeated failures -> accepted authentication -> session opened.
- Score independent dimensions separately: source rate, username diversity, failure/success ratio, connection duration/behavior, account privilege, and deviation from host baseline.
- Keep confidence and severity distinct. High event volume may be high confidence that probing occurred, but not necessarily high impact.
- Explain every score with contributing events and time window.
- Avoid hard-coded threat-intelligence verdicts from tutorial/lab IP addresses.
- Support IPv4, IPv6, loopback, mapped addresses, and correct port parsing.
- Handle NAT, shared egress, proxies, and distributed sources as attribution uncertainty.
- Do not block or alter PF based on a score during parser development.

## 6. Parser engineering requirements

- Treat syslog envelope parsing and sshd message parsing as separate layers.
- Support BSD syslog forms and common Linux/syslog variants; preserve raw timestamp text when year/timezone cannot be determined.
- Do not assume month/day timestamps include a year or timezone. Avoid fabricating either.
- Parse IPv4 and IPv6 with inet_pton; do not use whitespace-index extraction.
- Parse bracketed PID/process names and newer process labels such as sshd-session where present.
- Handle usernames containing unusual characters and messages with optional phrases.
- Bound line length and field sizes; reject or explicitly mark truncated/malformed records.
- Correctly handle partial lines at read boundaries; do not parse a fragment as a complete event.
- Preserve unknown message text for later analysis without unbounded memory use.
- Make parsing deterministic and side-effect free; detection/correlation belongs in a separate layer.
- Add reference samples for each observed message shape, negative cases, malformed input, IPv4/IPv6, long lines, embedded NUL, and version-specific variants.
- Test on FreeBSD 15.1 and keep portable C/POSIX assumptions explicit.

## 7. Current AirBotz baseline (reviewed on branch rebuild/minimal-pf-ssh)

Files reviewed:
- src/ssh/ssh_parser.c
- src/ssh/ssh.c
- tests/test_ssh.c
- tests/test_ssh_rotation.c
- Makefile

Current parser behavior:
- ssh_extract_address() searches after " from " and " by ", then validates candidate tokens using inet_pton.
- ssh_classify() recognizes a small set of authentication failures, successes, and connection-close messages.
- The parser currently returns only a coarse string category and does not expose a structured event object.

Known gaps to address in later stages:
- Message matching uses substring checks and may be overly broad or miss variants.
- Address extraction scans tokens after generic markers; it is not tied to a message grammar and can select an unrelated address in a complex line.
- No syslog envelope, timestamp, PID, username, port, auth method, reason, session ID, or protocol fields are normalized.
- "Received disconnect" and scanner behavior are not represented as a distinct, evidence-based detection.
- The reader uses a fixed 4096-byte fgets buffer. Oversized records may be split and fragments may be processed independently; this needs explicit bounded-record handling.
- The reader currently classifies each line independently; no time-window correlation or baseline exists.
- Existing tests cover a few IPv4/IPv6 extraction and classification examples plus log rotation/copytruncate behavior, not a broad OpenSSH corpus.

## 8. Staged work plan

- [x] R0. Record research references, initial taxonomy, detection hypotheses, telemetry boundaries, engineering requirements, and current parser gaps. Documentation only; no parser behavior changed.
- [ ] R1. Inventory and fingerprint the additional sample corpus. Record provenance, OS/distribution, OpenSSH version if known, log format, time coverage, and whether samples are synthetic, lab, honeypot, or production. Remove or redact secrets and personal data before committing reference samples.
- [ ] R2. Build a message catalogue from real samples. Group exact raw message shapes by event family and identify optional/variable fields.
- [ ] R3. Define normalized event schema and parser grammar before implementation.
- [ ] R4. Implement the syslog envelope and sshd message parser with strict bounds and safe malformed-record handling.
- [ ] R5. Add reference-sample-driven parser tests and regression coverage for every catalogued message shape.
- [ ] R6. Add time-window correlation for brute force, spraying-like behavior, enumeration, distributed campaigns, and success-after-failure.
- [ ] R7. Add explainable scoring and baseline-aware severity; calibrate false positives against benign samples.
- [ ] R8. Assess optional FreeBSD session/process telemetry for post-authentication behavior. Keep it separate from auth.log parsing and disabled unless explicitly configured.
- [ ] R9. Validate on FreeBSD, document performance/resource limits, and complete security review.

## 9. Sample corpus handling

The additional samples mentioned for this work must be reviewed before rules are finalized. For each file, capture:
- source/provenance and permission/license to use;
- platform and OpenSSH version, if known;
- whether the data is real, synthetic, lab, or honeypot;
- timestamp format/timezone and rotation/collection method;
- redaction status for IPs, usernames, hostnames, and secrets;
- expected event labels, if supplied, kept separate from parser ground truth.

Do not commit raw production logs or credentials. Prefer sanitized, minimal reference samples that preserve message structure. Keep original evidence outside the repository unless there is explicit permission and a clear data-handling decision.

## 10. Related outstanding audit note

IPC I4 is still awaiting validation. On the latest FreeBSD 15.1 run, `sudo ./tests/test_ipc` reported: `FAIL: idle IPC client was not timed out cleanly`. The unprivileged `make test` skips the root-only IPC integration test, so it does not clear this failure. Keep I4 open until the idle-client timeout behavior is diagnosed and the root integration test passes.

## 11. Research source links

- Fl1x, SSHD Logs Parse Forensics: https://fl1xh.github.io/posts/sshd_parse_forensics/
- kamer-heap, SSH Log Forensics: https://github.com/kamer-heap/ssh-log-forensics/
- Security Arsenal, TTY Log Forensics: https://securityarsenal.com/blog/tty-log-forensics-turning-honeypot-attacker-keystrokes-into-production-ssh-defense
- Noel-BijuJohn, HTB Brutus SSH Forensics: https://github.com/Noel-BijuJohn/htb-brutus-ssh-forensics


## 13. Additional research references and interpretation

### WarnHack — SSH Backdoor Detection / Forensic Audit Guide
URL: https://warnhack.com/blog/ssh-backdoor-detection-forensic-audit-guide
The page could not be retrieved reliably during this review. It is recorded as a pending reference, not as a source whose detailed claims have been verified. Before adopting any specific indicator, inspect the page and cross-check it against FreeBSD-native artifacts and the user's sample corpus.

### SSHwatch — SSH Forensic Analysis
URL: https://www.sshwatch.com/ssh-forensic-analysis-6-essential-commands-to-investigate-potential-breaches/
Useful themes: timeline reconstruction, authentication log aggregation, authorized_keys review, session recording, socket/process correlation, packet metadata and SSH binary/config integrity checks. Important portability corrections: examples using `ss`, Linux `/proc`, `md5sum`, `tlog`, `ausearch`, `aureport`, Sleuth Kit and tshark are not FreeBSD base assumptions. On FreeBSD, prefer `sockstat`, `procstat`, `netstat`, `sha256`, `mtree`, BSM tools and `tcpdump` where appropriate. File timestamps and hashes need a trusted baseline; a modified authorized_keys file is an indicator requiring investigation, not proof of compromise.

### DevCloudLab — SSH Access Auditing and Session Logging
URL: https://devcloudlab.com/blog/ssh-access-auditing-session-logging/
Useful themes: increase sshd log detail only after verifying FreeBSD's packaged OpenSSH supports the selected LogLevel; use key fingerprints and session lifecycle where logged; consider ForceCommand/session wrappers only as an explicit opt-in. The article's journald/systemd/auditd Linux workflow is not portable. FreeBSD's native `script(1)` may support controlled terminal recording, but it changes the login path and does not cover every non-interactive, SFTP, forwarding or escape scenario. Never claim tamper-proof logging from a local root-owned file alone.

### SSH-MITM documentation
URL: https://docs.ssh-mitm.at/
SSH-MITM is an active MITM proxy that terminates and forwards SSH connections, enabling visibility into authentication, session, file-transfer and forwarding behavior from an authorized interception position. It is useful as a research reference for what endpoint auth logs cannot reveal, but it is not a passive FreeBSD host sensor, not a default-system tool, and not suitable as a dependency for the AirBotz host agent. Deploying it would change the trust path and require explicit authorization and network architecture.

### Better Stack — SSH Logging
URL: https://betterstack.com/community/guides/logging/ssh-logging/
Useful themes: syslog facility, authentication log review, LogLevel trade-offs and operational logging. Linux-specific journalctl/systemd examples are excluded. AirBotz must parse actual FreeBSD syslog records and avoid assuming fixed awk field positions.

### SecureDebug — SSH Penetration Testing
URL: https://securedebug.com/ssh-penetration-testing-tools-and-techniques/
Useful threat-model themes: password/key attacks, weak server configuration, forwarding/tunneling, exposed versions and algorithm negotiation. Tools such as Nmap, Hydra, Ncrack, Metasploit and external OSINT are not dependencies for the native AirBotz sensor. Configuration assessment should use the installed `sshd -T`/configuration validation capabilities where supported, compare against version-aware policy, and never apply hardening changes automatically.

### SSH-Audit — Hardening Guides
URL: https://www.sshaudit.com/hardening_guides.html
Useful themes: review KEX, cipher, MAC, host-key and signature algorithms; hardening must be version-aware. The site lists a community-developed FreeBSD guide and explicitly distinguishes community guides from officially tested guides. AirBotz should inspect the actual installed OpenSSH version and effective configuration; do not copy Linux paths, algorithm lists, or directives blindly. Hardening recommendations should be advisory, explain compatibility impact, and require operator approval.

### FreeBSD primary documentation
- Security Event Auditing Handbook: https://docs.freebsd.org/en/books/handbook/audit/
- `audit(4)`: https://man.freebsd.org/cgi/man.cgi?query=audit&sektion=4
- `auditpipe(4)`: https://man.freebsd.org/cgi/man.cgi?query=auditpipe&sektion=4
- `praudit(1)`: https://man.freebsd.org/cgi/man.cgi?query=praudit&sektion=1
- `auditreduce(1)`: https://man.freebsd.org/cgi/man.cgi?query=auditreduce&sektion=1

These primary sources establish that FreeBSD has a BSM audit subsystem, audit trails, filtering/formatting tools, and an auditpipe live-event facility. Actual availability and event coverage must be checked on the target kernel and configuration; this is not equivalent to Linux auditd or a complete SSH session recorder.


## 14. Relationship to the wider AirBotz project

The SSHD parser is one service adapter within the broader FreeBSD-first detection and host-audit architecture documented in [AIRBOTZ_PROJECT_PLAN.md](AIRBOTZ_PROJECT_PLAN.md). The shared platform will separate native collectors, service parsers, normalized evidence, correlation, risk assessment and policy/enforcement.

SSHD-specific implementation must not absorb responsibilities belonging to other modules:
- PF/libpcap and optional Nmap handle network reconnaissance evidence.
- BSM/auditpipe and host auditors provide independent post-authentication/system evidence when configured.
- Samba, CUPS and other service parsers are conditional adapters, not SSH parser features.
- Host integrity/rootkit-inspired checks belong to a separate read-only audit engine.

The project dependency policy distinguishes FreeBSD base facilities from optional packages. FreeBSD provides tcpdump/libpcap and BSM audit facilities on the target platform, subject to capability and configuration checks. Nmap, Samba and CUPS are optional external packages. Nmap is an explicitly scoped active-audit tool, never a mandatory runtime dependency.



## 14. Initial sample-corpus findings (2026-11-28)

### 14.1 Confirmed local implementation target

- Operating system: FreeBSD 15.1-RELEASE-p7.
- OpenSSH: OpenSSH_10.0p2, OpenSSL 3.5.9 (29 Sep 2026).
- Current host `/var/log/auth.log`: approximately 977 KiB at collection time; no rotated `auth.log*` files were present.
- Additional files examined by the operator: `~/Downloads/auth.log` (4,100 sshd-matching lines in the initial count) and `~/Downloads/OpenSSH_2k.log` (2,000 sshd-matching lines). Their original publisher, platform, OpenSSH version, date range and license/permission still need to be recorded; do not assume they were generated by the local FreeBSD/OpenSSH 10.0p2 system.

### 14.2 Initial observed message shapes

The following exact or near-exact message bodies were observed in the supplied samples. Counts below are outputs of exploratory AWK grouping and are not yet authoritative event counts because the scripts used mutually exclusive substring branches and overlapping broad terms.

| Message shape / signature | Observed exploratory count | Parser interpretation |
|---|---:|---|
| `pam_unix(sshd:auth): check pass; user unknown` | 331 in auth.log; 135 in OpenSSH_2k.log | PAM account lookup/authentication context; do not equate this alone with a distinct network attempt |
| `pam_unix(sshd:auth): authentication failure; ... rhost=... user=...` | 147+ variants in auth.log; 277 in OpenSSH_2k.log | PAM authentication failure with optional remote host and username fields |
| `input_userauth_request: invalid user <name> [preauth]` | 45 admin; 43 blank-name variant; other names also observed | Invalid account request before authentication; preserve empty/missing username distinctly |
| `Disconnecting: Too many authentication failures [preauth]` | 189 in auth.log; 3 in OpenSSH_2k.log | Authentication-attempt limit reached; not necessarily password brute force (public-key offering can trigger it) |
| `reverse mapping checking getaddrinfo for <hostname> [<address>] failed - POSSIBLE BREAK-IN ATTEMPT!` | 80 and 2 in OpenSSH_2k.log for two observed variants | Reverse-DNS forward-confirmation mismatch warning; suspicious context, not proof of compromise or scanning |
| `Received signal 15; terminating.` | 4 in auth.log | sshd process lifecycle/termination event |
| `Server listening on <address-family/address> port <port>.` | 3 each for IPv4 wildcard and IPv6 wildcard on port 2222 | sshd listener/startup operational event, not an authentication event |
| `pam_unix(sshd:auth): authentication failure; ... rhost=...` with no `user=` field | Multiple variants | Parser must allow optional/missing username; do not shift fields positionally |

Other observed exploratory categories included `error:`, `fatal:`, `Starting session`, `Received signal`, `root` references and PAM records. These need a second pass using exact message bodies and independent tags. The earlier `other_sshd` and `unclassified` totals are not a single event family.

### 14.3 Corrections to the exploratory inventory

- Earlier AWK commands used `else if`; each record was assigned to only the first matching category. This undercounts overlapping attributes and can hide event dimensions.
- The `Disconnected` and `Received disconnect` checks overlap semantically and may have counted the same message in separate runs. They must be distinct only when the actual OpenSSH message grammar supports that distinction.
- A broad search for `root` is not a root-login detector. It can match usernames, paths, hostnames or unrelated text. Root access must be derived from a parsed authentication-success record and its normalized account field.
- `PAM authentication failure` and `Failed password` may describe the same authentication attempt at different layers. Correlation must avoid counting them as two independent attempts without a stable process/connection/time key.
- `POSSIBLE BREAK-IN ATTEMPT` is OpenSSH's wording for a reverse-mapping check failure. Treat it as a DNS consistency warning and contextual signal, not a verdict.
- `Too many authentication failures` indicates the server disconnected after an authentication-attempt limit. It does not by itself establish password guessing.
- Operational records such as listener startup and SIGTERM must be parsed but excluded from authentication attack counters.

### 14.4 Required parser fields suggested by these samples

The normalized event model must support:
- event family and subtype;
- raw sshd message body (bounded) and parse status;
- syslog timestamp, hostname, program/process name and PID where present;
- username with explicit states: present, absent, empty, invalid-account label, or unknown;
- remote hostname (if supplied), remote address and port as independent optional fields;
- pre-authentication marker;
- PAM facility/module and PAM message subtype;
- authentication method/result when actually present;
- disconnect reason / attempt-limit reason;
- operational lifecycle action, signal, listener address family and port;
- independent tags/attributes so one event can carry multiple facts without being forced into a single substring bucket.

### 14.5 Next research actions

1. Record provenance, source URLs, licenses/permissions, platform and OpenSSH versions for both downloaded corpora.
2. Extract a bounded list of distinct raw sshd message bodies for each sample file, retaining exact punctuation and optional-field variants.
3. Build a message catalogue with stable IDs and mark each entry as observed, inferred, or not yet verified.
4. Define the normalized event schema and correlation keys before changing parser behavior.
5. Turn each accepted message shape into a named automated test case using the phrase “reference sample”; unknown and malformed messages also need explicit test cases.
6. Re-run counts with independent predicates/tags rather than mutually exclusive `else if` classification.
