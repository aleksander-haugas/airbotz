# AirBotz

Minimal FreeBSD security daemon focused exclusively on PF and SSH.

## Scope

- PF status inspection and safe PF table operations.
- SSH authentication log tailing and event classification.
- IPv4/IPv6 validation with inet_pton.
- Small configuration, logging, signal handling and clean shutdown.

No web panel, REST API, Nginx/FTP parsers, AI integration, generic rule engine,
persistent ban database, or automatic blocking is included.

## Build

On FreeBSD:

    make
    make test

Run in the foreground while developing:

    ./airbotz -c config/airbotz.conf

PF commands require suitable privileges and pfctl. The daemon does not enable PF,
change firewall policy, or block addresses automatically. PF table mutations are
available through the PF module API and are deliberately not wired to SSH events.

## Configuration

Copy config/airbotz.conf to /usr/local/etc/airbotz/airbotz.conf and adjust paths.
The SSH log path defaults to /var/log/auth.log on FreeBSD.

## Design

main -> core lifecycle -> config/logger/PF/SSH modules.
The SSH module observes and classifies; policy and enforcement are separate future work.
