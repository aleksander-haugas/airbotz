# AirBotz

**FreeBSD-first host security detection, auditing and controlled response.**

AirBotz is being developed as a modular security platform for FreeBSD. Its current implemented core is deliberately small: PF management, SSH authentication-log observation, persistent address state and a root-only local control interface. The broader product roadmap adds native telemetry, service-specific parsers, cross-source detection, host-integrity audits and optional active network assessment.

The project is developed and validated incrementally on FreeBSD. Planned modules are not represented as implemented features.

## Project direction

See **[docs/AIRBOTZ_PROJECT_PLAN.md](docs/AIRBOTZ_PROJECT_PLAN.md)** for the architecture, dependency policy, service roadmap, FreeBSD-native audit design, Nmap integration strategy and validation criteria.

Current workstreams:

- [SSHD parser research](docs/SSHD_PARSER_RESEARCH.md)
- [Security audit TODO](AUDIT_TODO.md)

## Current implemented core

- PF status inspection and explicit operations on separate temporary and permanent tables.
- SSH authentication log tailing and event classification.
- IPv4/IPv6 validation with `inet_pton`.
- Persistent permanent and expiring temporary IP lists.
- Transactional address management with PF rollback on persistence failures.
- Root-only local Unix socket control interface.
- Small configuration, logging, signal handling and clean shutdown.

The SSH module currently observes and classifies a limited set of authentication and connection events. It is not yet the planned full SSH detection engine. Cross-service correlation, Nmap integration, Samba/CUPS parsers and host-security audits are roadmap items.

## Platform and dependencies

- Target: FreeBSD 15.x initially.
- Core: C and FreeBSD/POSIX facilities; no mandatory Nmap, Samba, CUPS or web-server dependency.
- Packet metadata: FreeBSD provides tcpdump and libpcap in the base environment; actual build/runtime capability will be checked.
- Nmap: optional external package for explicitly authorized active audits; not part of FreeBSD base and not required by the daemon.
- Samba, CUPS, DNS, HTTP, mail and other service adapters are conditional on those services being installed and configured.
- BSM auditing is a FreeBSD facility, but auditd, audit policy, kernel support and event coverage must be verified on each host.
- pkg audit is an optional package-vulnerability capability; it does not replace base-system security advisories or integrity verification.

AirBotz will not silently install packages, enable services, change firewall policy, rewrite service configuration or scan networks. Optional integrations require explicit operator configuration.

## Build and test

On FreeBSD:

    make
    make test

The IPC integration test runs with root privileges; when the test suite is run as an unprivileged user, that test reports SKIP.

Run in the foreground while developing:

    sudo ./airbotz -c config/airbotz.conf

The daemon stays in the foreground. Control commands use its local socket:

    sudo ./airbotz status
    sudo ./airbotz ip list

When using a non-default configuration, pass the same file to the CLI:

    sudo ./airbotz -c /usr/local/etc/airbotz/airbotz.conf status
    sudo ./airbotz -c /usr/local/etc/airbotz/airbotz.conf ip list
    sudo ./airbotz ip add 192.0.2.10 permanent
    sudo ./airbotz ip add 192.0.2.20 temporary 3600
    sudo ./airbotz ip remove 192.0.2.10 permanent
    sudo ./airbotz ip remove 192.0.2.20 temporary

The control socket defaults to `/var/run/airbotz.sock`, is created with root-only permissions (0600), and checks the connecting process credentials. The CLI sends requests to the daemon; it never modifies PF or persistence directly. The `status` command reports persisted managed-IP counts, the live PF enabled/disabled state, and the actual entry counts in both configured PF tables. Differences between persisted counts and PF table counts indicate drift that requires investigation; AirBotz does not automatically delete unrecognized PF entries. Temporary durations are limited to 1 through 31,536,000 seconds.

## Install as a FreeBSD service

Install the binary and rc.d script:

    sudo make install

Create the active configuration from the installed sample and edit it:

    sudo cp /usr/local/etc/airbotz/airbotz.conf.sample /usr/local/etc/airbotz/airbotz.conf
    sudo ee /usr/local/etc/airbotz/airbotz.conf

Enable automatic startup only after validation and explicit approval:

    sudo sysrc airbotz_enable="YES"

Manage the service:

    sudo service airbotz start
    sudo service airbotz status
    sudo service airbotz restart
    sudo service airbotz stop

The rc.d integration uses FreeBSD's daemon(8) to detach the process and maintain /var/run/airbotz.pid. AirBotz itself stays in the foreground. The service normally runs as root to read protected authentication logs and administer PF.

## Configuration and safety

The SSH log defaults to /var/log/auth.log. PF is enabled in the sample configuration, but AirBotz does not enable PF or change firewall policy. It uses the existing tables configured in /etc/pf.conf:

- `pf_temp_table=airbotz_temp`
- `pf_perm_table=airbotz_perm`

The local control socket is configured with `socket_path` and defaults to `/var/run/airbotz.sock`.

The persistence directory defaults to `/var/db/airbotz` and can be changed with `storage_dir`:

- `permanent.list`: one IPv4 or IPv6 address per line.
- `temporary.list`: address followed by UTC expiry in `YYYY-MM-DDTHH:MM:SSZ` format.

The directory is restricted to its owner (0700); list files are restricted to owner read/write (0600). Updates use temporary files, fsync and atomic rename.

At startup, AirBotz restores permanent entries and unexpired temporary entries to their corresponding PF tables. Expired temporary entries are removed from PF and the persisted list. PF operations are not triggered by SSH events; automatic blocking remains disabled.

## Design principles

- Collection, parsing, correlation, risk assessment, policy and enforcement remain separate.
- Parsers are bounded and preserve unknown events safely.
- Findings must be explainable and distinguish confidence from severity.
- Host audits are read-only by default and compare against trusted baselines.
- Optional active scanning requires explicit scope and authorization.
- No automatic package installation, service changes, remediation or firewall changes.
- A detection indicator is not proof of compromise; local-only rootkit checks have fundamental limits.

