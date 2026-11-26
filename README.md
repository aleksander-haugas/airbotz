# AirBotz

Minimal FreeBSD security daemon focused exclusively on PF and SSH.

## Scope

- PF status inspection and explicit operations on separate temporary and permanent tables.
- SSH authentication log tailing and event classification.
- IPv4/IPv6 validation with inet_pton.
- Atomic persistence for permanent and expiring temporary IP lists.\n- Small configuration, logging, signal handling and clean shutdown.

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

The rc.d integration uses FreeBSD's daemon(8) to detach the process and
maintain /var/run/airbotz.pid. AirBotz itself stays in the foreground; this
keeps signal handling and development/testing straightforward. The service
runs with the privileges of the rc.d launcher (normally root), which are
needed to read protected authentication logs and administer PF.

## Configuration and safety

The SSH log path defaults to /var/log/auth.log on FreeBSD. PF is enabled in
the sample configuration but AirBotz does not enable PF or change firewall
policy. It uses the existing PF tables configured in /etc/pf.conf:

- pf_temp_table=airbotz_temp
- pf_perm_table=airbotz_perm

The PF module exposes distinct add/delete operations for each table. The
temporary table is a separate classification/storage table; entries do not
expire automatically merely because they are in that table. Expiration
scheduling is future work. PF table mutations are not wired to SSH events,
so automatic blocking remains disabled.

## Design

main -> core lifecycle -> config/logger/PF/SSH modules.
The SSH module observes and classifies; policy and enforcement are separate future work.
