# AirBotz

Minimal FreeBSD security daemon focused exclusively on PF and SSH.

## Scope

- PF status inspection and explicit operations on separate temporary and permanent tables.
- SSH authentication log tailing and event classification.
- IPv4/IPv6 validation with `inet_pton`.
- Persistent permanent and expiring temporary IP lists.
- Small configuration, logging, signal handling and clean shutdown.

No web panel, REST API, Nginx/FTP parsers, AI integration, generic rule engine,
or automatic blocking from SSH events is included.

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

Enable automatic startup only after validation and explicit approval:

    sudo sysrc airbotz_enable="YES"

Manage the service:

    sudo service airbotz start
    sudo service airbotz status
    sudo service airbotz restart
    sudo service airbotz stop

The rc.d integration uses FreeBSD's daemon(8) to detach the process and
maintain /var/run/airbotz.pid. AirBotz itself stays in the foreground.
The service normally runs as root to read protected authentication logs
and administer PF.

## Configuration and safety

The SSH log defaults to /var/log/auth.log. PF is enabled in the sample
configuration, but AirBotz does not enable PF or change firewall policy.
It uses the existing tables configured in /etc/pf.conf:

- `pf_temp_table=airbotz_temp`
- `pf_perm_table=airbotz_perm`

The persistence directory defaults to `/var/db/airbotz` and can be changed
with `storage_dir`:

- `permanent.list`: one IPv4 or IPv6 address per line.
- `temporary.list`: address followed by UTC expiry in
  `YYYY-MM-DDTHH:MM:SSZ` format.

The directory is restricted to its owner (0700); list files are restricted
to owner read/write (0600). Updates use temporary files, fsync and atomic
rename.

At startup, AirBotz restores permanent entries and unexpired temporary
entries to their corresponding PF tables. Expired temporary entries are
removed from PF and the persisted list. PF operations are not triggered by
SSH events; automatic blocking remains disabled.

## Design

main -> core lifecycle -> config/logger/storage/PF/SSH modules.
The SSH module observes and classifies; policy and enforcement remain separate.
