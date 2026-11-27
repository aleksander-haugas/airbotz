# AirBotz — Project Architecture and Security Roadmap

Status: strategic design baseline; roadmap only. This document does not claim that planned modules are implemented.
Target platform: FreeBSD 15.x initially, with version-aware support policy.
Implementation direction: hand-written C, FreeBSD/POSIX interfaces, minimal mandatory dependencies, modular collectors and parsers.

## 1. Project vision

AirBotz is intended to become a modular host-security detection, auditing and response platform for FreeBSD systems. It should protect both minimal servers and systems running common infrastructure services.

The product combines:
1. Host and service discovery: identify what is installed, enabled, running and listening.
2. Telemetry collection: consume native logs, audit events, firewall information, packet metadata and host state.
3. Protocol/service parsers: convert source-specific evidence into normalized events.
4. Correlation and detection: identify attack patterns across time and telemetry sources.
5. Security auditing: assess configuration, integrity, exposure and known vulnerabilities.
6. Controlled response: alert, preserve evidence and, when explicitly enabled, manage AirBotz-owned PF entries.

The design goal is contextual detection and practical response, not a collection of unrelated log filters. Claims of superiority over Fail2ban, SSHGuard or commercial products must wait for repeatable benchmarks on representative datasets.

## 2. Product principles

- FreeBSD-first. Do not assume Linux paths, systemd, journald, auditd syntax, iptables, nftables, eBPF or Linux /proc.
- C implementation with native APIs and tools wherever practical.
- No mandatory third-party runtime dependency for the core daemon.
- Optional integrations are capability-detected and clearly reported as unavailable when absent.
- Parsers are deterministic, bounded, side-effect-free and fixture-tested.
- Unknown input is preserved safely as unknown; it is never silently promoted to a malicious verdict.
- Separate collection, parsing, correlation, risk assessment, policy and enforcement.
- Every detection includes evidence, time window, confidence and severity.
- Never equate an indicator with proof of compromise.
- No automatic remediation or destructive configuration changes.
- Resource ceilings, rate limits, timeouts and failure-safe behavior are requirements, not later optimizations.
- Raw production logs, credentials, private keys and sensitive host data must not be committed to the repository.

## 3. Dependency and capability policy

AirBotz distinguishes the FreeBSD base system from optional packages. Presence in the Ports Collection or availability through pkg does not mean a component is installed by default.

### 3.1 FreeBSD base capabilities

The initial target is FreeBSD 15.x. The following are native system facilities or base utilities and should be preferred when available:

| Capability | Intended use |
|---|---|
| OpenSSH / syslog / auth.log | SSH authentication and lifecycle events |
| PF / pfctl / pflog | Firewall state, managed block tables and packet-log evidence |
| tcpdump and libpcap | Packet metadata and capture; libpcap is available with the FreeBSD base environment on the target platform |
| BSM audit / auditd / auditpipe / praudit / auditreduce | Security event auditing and live or post-event evidence, subject to kernel and audit configuration |
| sockstat / netstat / procstat / ps | Listening sockets, connection and process context |
| mtree / sha256 / stat / find | File integrity and host-state inspection |
| freebsd-update IDS | Comparison of base-system files against update metadata |
| service / rc.conf / rc.d / sysrc | Service inventory and startup configuration |
| cron / periodic logs and configuration | Scheduled-task and persistence auditing |
| NFS/RPC, inetd, FTP and Sendmail components | Service-specific monitoring when configured and running |

Runtime capability checks are mandatory. A tool may exist while its service, kernel feature, audit policy, device or required permission is unavailable.

### 3.2 Optional external tools and packages

| Tool / service | Classification | AirBotz policy |
|---|---|---|
| Nmap | External package; not part of the FreeBSD base system | Optional active-audit integration. Never required by the core daemon. Scan only explicitly authorized targets and configured scope. |
| Samba | External package | Enable SMB parser only when installed/running or when its logs are configured. |
| CUPS | External package | Enable CUPS/IPP audit only when present. Also inspect printer network exposure independently of CUPS. |
| BIND, Apache, Nginx, Dovecot, database servers, SNMP agents and similar software | External packages | Future service adapters; never assume they are installed. |
| pkg / pkg audit | Package-management capability; pkg(8) is bootstrapped on supported FreeBSD versions, but package database and audit data availability must be checked | Optional package vulnerability audit. Do not install or update packages automatically. |
| rkhunter and other third-party rootkit scanners | External tools | Research references only; AirBotz should build a FreeBSD-native audit engine rather than depend on or blindly wrap Linux-oriented checks. |

The pcap library is not to be confused with Nmap. Packet capture and passive metadata analysis can use FreeBSD's native libpcap/tcpdump facilities. Nmap provides active probing and is a separate optional dependency. Build and runtime probes must verify the actual target environment rather than assume a library path or ABI.

### 3.3 Dependency modes

- **Core mode:** daemon, PF integration, SSH log reader, storage, IPC and status; no Nmap or service package required.
- **Native telemetry mode:** PF, libpcap/tcpdump, BSM and host inventory, each capability-gated.
- **Optional service mode:** Samba, CUPS, DNS, HTTP, mail, NFS/RPC, FTP and other adapters only when their services are present.
- **Active audit mode:** Nmap integration, explicitly enabled and scoped by the operator.
- **Extended vulnerability mode:** pkg audit and vulnerability database access when available; no automatic upgrades.

## 4. Target architecture

```
+----------------------+       +--------------------------+
| Native collectors    |       | Optional integrations    |
| syslog/auth.log      |       | Nmap active audit        |
| BSM/auditpipe        |       | pkg audit / VuXML        |
| PF/pflog/pfctl       |       | Samba / CUPS logs        |
| libpcap/tcpdump      |       | HTTP / DNS / mail logs   |
| sockets/processes    |       | Other installed services |
| filesystem/config    |       |                          |
+----------+-----------+       +------------+-------------+
           +-------------------------------+
                           |
                 +---------v----------+
                 | Normalized event   |
                 | and evidence model |
                 +---------+----------+
                           |
                 +---------v----------+
                 | Service parsers    |
                 | and host auditors |
                 +---------+----------+
                           |
                 +---------v----------+
                 | Correlation and    |
                 | detection engine  |
                 +---------+----------+
                           |
                 +---------v----------+
                 | Risk / confidence  |
                 | / severity         |
                 +---------+----------+
                           |
                 +---------v----------+
                 | Policy and response|
                 | alerts / PF / audit|
                 +--------------------+
```

Collectors obtain evidence; parsers normalize it; detectors correlate it; the policy layer decides what to do. A parser must never independently add or delete PF entries.

## 5. Normalized event model

The schema will be finalized before broad parser implementation. Candidate fields:

- event timestamp and timestamp quality (absolute, local-without-year, inferred, unavailable);
- source collector and parser identifier/version;
- host identity and service/process name, PID where trustworthy;
- event family and event type;
- source/destination address and port, protocol;
- username/account, authentication method and session identifier when available;
- result, reason and normalized status;
- raw-record reference or bounded sanitized excerpt;
- evidence attributes and parser warnings;
- confidence and severity assigned by detection, not by parsing;
- correlation key and observation window.

Do not fabricate missing timestamps, identities, ports or session relationships. Preserve uncertainty explicitly.

## 6. Service and telemetry roadmap

### 6.1 Priority service parsers

| Module | Evidence and detection goals |
|---|---|
| SSHD | Authentication failures/success, invalid users, spraying-like activity, connection lifecycle, privileged access and session correlation |
| PF / network reconnaissance | TCP/UDP scans, horizontal/vertical sweeps, SYN patterns, connection fan-out and firewall state correlation |
| BSM audit | Login, privilege, process, file and configuration events selected by the host audit policy |
| Login / SU | Login accounting, privilege transitions and suspicious administrative access |
| SMB / Samba | Authentication abuse, share/user enumeration, unusual access, session patterns and smb.conf integrity |
| CUPS / IPP / printer exposure | Administrative access, queue/configuration changes, unexpected jobs and exposed printer services |
| NFS / RPC | Export and mount exposure, RPC enumeration and anomalous access |
| DNS | Unusual queries, zone-transfer attempts, resolver abuse and service/configuration changes |
| HTTP / HTTPS | Access-log anomalies, probing, path traversal indicators, authentication abuse and server configuration changes |
| SMTP / mail | Relay abuse, authentication failures, recipient enumeration patterns and anomalous delivery |
| FTP / inetd / legacy | Anonymous access, authentication abuse, transfers and unexpected legacy listeners |
| DHCP / SNMP | Rogue DHCP indicators, lease anomalies, SNMP exposure and enumeration |

These modules are conditional. Samba, CUPS, common web servers, BIND, Dovecot and database servers are not FreeBSD base components. The service inventory must discover actual installations and runtime exposure instead of assuming a default installation.

### 6.2 Host and platform auditors

- Service exposure auditor: compare installed/enabled/running services with listening sockets and PF exposure.
- Configuration auditor: inspect service configuration using version-aware, read-only checks.
- File integrity auditor: trusted baselines for critical binaries, libraries, startup files, SSH keys, service configuration and scheduled tasks.
- Account and privilege auditor: unexpected accounts, UID 0 accounts, group membership, login shells, authorized_keys and privilege configuration.
- Persistence auditor: rc.conf/rc.d, cron, periodic, loader configuration, kernel modules and other startup mechanisms.
- Process and socket auditor: correlate listeners, owning processes, executable paths and process metadata where the OS permits.
- Package vulnerability auditor: inspect installed packages and known vulnerability data when pkg audit is available.
- Network exposure auditor: inventory local listeners and optionally perform scoped active scans using Nmap.

## 7. FreeBSD-native security audit engine (rkhunter-inspired)

AirBotz will include a dedicated read-only host security audit module. It is inspired by the goals of tools such as rkhunter, but will be designed around FreeBSD's own security model and native evidence.

### 7.1 Audit categories

1. Base-system integrity: mtree specifications and freebsd-update IDS results, with update-aware exceptions.
2. Critical file integrity: SHA-256 and metadata comparisons against a trusted baseline stored outside the writable trust boundary where possible.
3. Kernel and modules: loaded modules, unexpected module paths, kernel identity and configuration drift.
4. Startup and persistence: rc.conf, rc.d, loader.conf, cron, periodic and other configured startup mechanisms.
5. Accounts and privilege: UID 0, unexpected users/groups, shell changes, authorized_keys and privilege-policy changes.
6. Network exposure: listeners, process ownership, unexpected services, PF policy and optional Nmap results.
7. Service configuration: SSHD, PF, SMB, CUPS, DNS, mail, web, NFS and FTP checks when present.
8. Package security: installed package inventory and pkg audit findings when the package database and vulnerability data are available.
9. Log and audit health: auditd status, log permissions, missing/rotated sources, time synchronization and evidence gaps.
10. Suspicious artifacts: unusual writable executable locations, unexpected setuid/setgid files, suspicious startup references and selected file metadata anomalies.

### 7.2 Trust and limitations

- A baseline generated on an already-compromised host is not trustworthy.
- Local root compromise can alter local files, logs, tools and baseline data. Prefer offline, read-only or remote baselines and remote log retention.
- mtree and freebsd-update IDS are useful integrity mechanisms, not proof that a host is clean.
- A same-host scanner cannot reliably prove absence of kernel-level rootkits or hidden processes when the kernel itself is compromised.
- Heuristics such as unusual file names, timestamps, ports or setuid bits are indicators requiring review, not verdicts.
- Reports must distinguish confirmed configuration facts, integrity mismatches, heuristic warnings and unavailable checks.
- Audit is read-only by default. No automatic deletion, quarantine, permission change, package upgrade, service disablement or configuration rewrite.

### 7.3 Audit output

Each finding should include check ID, category, affected object, observed value, expected/baseline value, evidence source, severity, confidence, remediation guidance, and whether the check was skipped or unavailable. Reports should be deterministic and machine-readable, with bounded output and redaction of secrets.

## 8. Nmap and packet-capture strategy

- Passive observation: use libpcap and/or tcpdump on the local host for packet metadata; do not attempt to decrypt SSH, TLS or other encrypted application traffic.
- Active audit: Nmap may discover exposed ports and service fingerprints on explicitly authorized targets. It is optional and must be separately enabled.
- Scope: default target is the local host only if the operator explicitly selects it. Network/subnet scanning requires explicit target and authorization.
- Safety: rate limits, timeouts, scan profiles, exclusions, audit trail and dry-run preview are required. No stealth/evasion profiles.
- Do not launch Nmap from the core daemon's hot path. Use a bounded worker/process interface and parse stable XML output rather than scraping terminal presentation.
- Nmap findings are observations, not proof of vulnerability. Version detection may be inaccurate or deliberately obscured.

## 9. Detection and response model

Detection pipeline:
1. Collect bounded evidence.
2. Parse into normalized events.
3. Correlate across time, service, process, account and network dimensions.
4. Evaluate deterministic rules and baseline deviations.
5. Assign confidence and severity separately.
6. Produce an explainable finding with supporting evidence.
7. Apply operator-configured policy.

Response stages:
- Observe and report.
- Alert and preserve evidence.
- Recommend operator action.
- Optional temporary PF block with expiry.
- Optional permanent PF block only under explicit policy and review.

All automated blocking remains default-off during development. Protect management addresses, loopback, trusted networks and recovery paths. Use AirBotz-owned PF tables only. Never delete unknown PF entries or alter unrelated firewall rules.

## 10. Development and validation roadmap

### Project definition
- [x] P0. Establish FreeBSD-first project direction and initial SSHD research baseline.
- [ ] P1. Approve this architecture and dependency policy against the actual supported FreeBSD release matrix.

### Core reliability (existing workstream)
- [ ] Resolve IPC I4 idle-client timeout failure and rerun root integration tests.
- [ ] Finish PF reconciliation only when exclusive table ownership or an atomic ownership model is proven.
- [ ] Continue storage, IPC, configuration, daemon and regression audits.

### Telemetry and parsers
- [ ] T1. Inventory and fingerprint sanitized SSHD sample corpus.
- [ ] T2. Define normalized event schema and parser contract.
- [ ] T3. Implement SSHD parser from real fixtures.
- [ ] T4. Implement PF/network scan metadata collector and detector.
- [ ] T5. Evaluate BSM/auditpipe collection and event coverage.
- [ ] T6. Implement service discovery and capability reporting.
- [ ] T7. Add Samba/SMB parser.
- [ ] T8. Add CUPS/IPP and printer-exposure checks.
- [ ] T9. Add NFS/RPC, DNS, HTTP, SMTP, FTP/inetd and other adapters according to demand.
- [ ] T10. Add bounded cross-source correlation and explainable detections.

### Host auditing
- [ ] A1. Define trusted-baseline format, lifecycle, storage and remote/offline trust options.
- [ ] A2. Implement read-only base-system and critical-file integrity checks.
- [ ] A3. Implement account, privilege, startup and persistence audits.
- [ ] A4. Implement kernel/module, process and listening-socket audits.
- [ ] A5. Implement service-specific configuration audits.
- [ ] A6. Integrate pkg audit as an optional capability.
- [ ] A7. Design and implement Nmap active-audit adapter with explicit scope and safe defaults.
- [ ] A8. Produce machine-readable forensic and security-audit reports.

### Response, quality and release
- [ ] Q1. Add adversarial parser fixtures, fuzzing, malformed input and resource-exhaustion tests.
- [ ] Q2. Measure CPU, memory, I/O and event-loss behavior under load.
- [ ] Q3. Validate on supported FreeBSD releases and representative service configurations.
- [ ] Q4. Benchmark detection quality against Fail2ban/SSHGuard on identical labeled datasets.
- [ ] Q5. Document limitations, false-positive rates, precision/recall and response safeguards.
- [ ] Q6. Keep automatic response disabled until safety tests and operator policy are approved.

## 11. Release philosophy

The initial release should be a reliable FreeBSD host sensor and PF manager with SSH visibility, not an unfinished promise of a universal IDS. Additional parsers and audit modules are enabled progressively after fixtures, capability detection, resource limits and FreeBSD validation exist.

A module is not considered complete because it compiles. Completion requires:
- documented event sources and coverage limitations;
- sanitized fixtures from real or representative environments;
- positive and negative tests;
- malformed/oversized/binary input handling;
- performance and resource bounds;
- FreeBSD validation;
- operational documentation and a recorded commit.

## 12. Primary references

- FreeBSD Security Handbook: https://docs.freebsd.org/en/books/handbook/security/
- FreeBSD Security Event Auditing: https://docs.freebsd.org/en/books/handbook/audit/
- FreeBSD Ports and Packages: https://docs.freebsd.org/en/books/handbook/ports/
- FreeBSD pcap(3): https://man.freebsd.org/cgi/man.cgi?manpath=FreeBSD+15.1-RELEASE+and+Ports&query=pcap&sektion=3
- FreeBSD mtree(8): https://man.freebsd.org/cgi/man.cgi?query=mtree&sektion=8
- FreeBSD freebsd-update(8): https://man.freebsd.org/cgi/man.cgi?query=freebsd-update&sektion=8
- FreeBSD pkg-audit(8): https://man.freebsd.org/cgi/man.cgi?query=pkg-audit&sektion=8
- Nmap reference guide: https://nmap.org/book/man.html
