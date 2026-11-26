# AirBotz

Minimal FreeBSD security daemon focused exclusively on PF and SSH.

## Scope

- PF status inspection and safe PF table operations.
- SSH authentication log tailing and event classification.
- IPv4/IPv6 validation with inet_pton.
- Small configuration, logging, signal handling and clean shutdown.

No web panel, REST API, Nginx/FTP parsers, AI integration, generic rule engine,
persistent ban database, or automatic blocking is included.

## Build and test

On FreeBSD:

    make
    make test

Run in the foreground while developing:

    ./airbotz -c config/airbotz.conf

## Install as a FreeBSD service

Install the binary and rc.d script:

    sudo make install

Create the active configuration from the installed sample and edit it:

    sudo cp /usr/local/etc/airbotz/airbotz.conf.sample /usr/local/etc/airbotz/airbotz.conf
    sudo ee /usr/local/etc/airbotz/airbotz.conf

Enable automatic startup:

    sudo sysrc airbotz_enable="YES"

Manage the service:

    sudo service airbotz start
    sudo service airbotz status
    sudo service airbotz restart
    sudo service airbotz stop

The rc.d integration uses FreeBSD's `rc.subr` background-process support and
tracks the daemon with `/var/run/airbotz.pid`. AirBotz itself stays in the
foreground; this keeps signal handling and development/testing straightforward.
The service runs with the privileges of the rc.d launcher (normally root), which
are needed to read protected authentication logs and administer PF when enabled.

## Configuration and safety

The SSH log path defaults to `/var/log/auth.log` on FreeBSD. Adjust paths and
settings before enabling the service.

PF commands require suitable privileges and `pfctl`. The daemon does not enable
PF, change firewall policy, or block addresses automatically. PF table mutations
are available through the PF module API and are deliberately not wired to SSH events.

## Design

main -> core lifecycle -> config/logger/PF/SSH modules.
The SSH module observes and classifies; policy and enforcement are separate future work.
