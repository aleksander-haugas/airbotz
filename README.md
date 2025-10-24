# Airbotz – Intrusion Detection & Prevention System for FreeBSD

![Airbotz](https://img.shields.io/badge/Status-Active-brightgreen) ![Language C](https://img.shields.io/badge/Language-C-blue)

**Airbotz** is an **Intrusion Detection & Prevention System (IDS/IPS)** specifically designed for **FreeBSD**, optimized to work with **PF (Packet Filter)**, protecting servers from network attacks, brute force attempts, and malicious activity across SSH, FTP, Nginx, and Minecraft services.

---

## Key Features

* Native integration with **PF/pflog** for real-time protection.
* Detection of **port scans, SYN/UDP floods, ICMP floods**, and other network anomalies.
* Service-level protection:

  * **SSH / SFTP** – failed logins, invalid users, suspicious disconnects
  * **FTP** – failed logins, anonymous access, suspicious uploads/downloads
  * **Nginx / Web** – brute force, SQL injection, XSS, directory scanning, data exfiltration
  * **Minecraft** – login failures, chat spam, block break/place floods
* **Configurable rule system** with thresholds, time windows, action types, and ban durations.
* **Temporary and permanent ban management** with automatic escalation logic.
* **Smart counters** to prevent premature bans and detect recurrences.
* Detailed logging at `/var/log/airbotz.log`.
* Low resource usage (<10MB RAM, near-zero CPU when idle).

---

## 🧩 Requirements

- **Operating System:** FreeBSD 13.2+ / 14.x  
- **Dependencies:**  
```

libpcap
pthread

````
- **PF firewall** enabled with `pflog0` configured:
```bash
echo 'pflog_enable="YES"' >> /etc/rc.conf
service pflog start
````

---

## ⚙️ Installation from GitHub

1. **Clone the repository:**

   ```bash
   git clone https://github.com/aleksander-haugas/airbotz.git /usr/local/src/airbotz
   cd /usr/local/src/airbotz
   ```

2. **Build:**

   ```bash
   make
   ```

3. **Install binaries:**

   ```bash
   make install
   ```

   This will install the following files:

   ```
   /usr/local/bin/airbotz
   /usr/local/etc/airzox.conf
   /var/db/airbotz/airbotz.dat
   /var/log/airbotz_alerts.json
   /var/log/airbotz.log
   ```

4. **Set proper permissions:**

   ```bash
   chown root:wheel /usr/local/bin/airbotz
   chmod 755 /usr/local/bin/airbotz
   mkdir -p /var/db/airbotz /var/log/airbotz
   chmod 700 /var/db/airbotz
   ```

---

## 🔧 Basic Configuration (`/usr/local/etc/airzox.conf`)

Example event-based configuration:

```ini
# Service   Event                  Attempts  Time(s)  Action        Duration
sshd        ssh_failed_login       5         300      ban_temp      600
vsftpd      ftp_login_failed       6         600      ban_temp      900
pflog       portscan               15        60       log_only      0
nginx       sql_injection_attempt  10        60       ban_temp      0
```

Each line defines:

```
service   event_type   attempt_threshold   time_window   action   ban_duration
```

**Available actions:**

* `ban_temp` – Temporary ban
* `ban_perm` – Permanent ban
* `alert_only` – Only alert
* `log_only` – Only log
* `watchlist` – Monitor suspicious activity


---

## ▶️ Usage

1. **Start the service manually:**

   ```bash
   service airbotz start
   ```

2. **View real-time alerts:**

   ```bash
   tail -f /var/log/airbotz_alerts.json
   ```

3. **Check current status:**

   ```bash
   airbotz status
   ```

---

## Escalation Logic

* If an IP repeatedly hits the threshold, **temporary bans are automatically promoted to permanent**.
* Permanent bans are never overwritten by temporary bans.

---

## 🧩 PF Integration

To ensure proper packet capture on `pflog0`, make sure you have rules with the `log` keyword enabled in `/etc/pf.conf`:

```pf
# Basic example
block in log all
pass in log on egress proto tcp to port 80
pass out all keep state
```

Then reload your PF rules:

```bash
pfctl -f /etc/pf.conf
```

* Banned IPs are automatically added to PF tables:

  * Temporary: `airbotz_temp`
  * Permanent: `airbotz_perm`

* Temporary bans expire automatically, and PF tables are synchronized at startup.

---

## 🧠 Example Alert Output

```
{
  "timestamp": "2025-10-24T18:25:43+0000",
  "service": "pflog",
  "event": "portscan",
  "ip": "10.1.10.200",
  "info": "portscan detected: 15 unique ports (window=60s) ports=20-80"
}
```

---

## 🛠️ Development

Build in debug mode:

```bash
make clean
make DEBUG=1
```

Format code:

```bash
clang-format -i src/*.c include/*.h
```

---

## Contributing

1. Fork the repository.
2. Create a branch for your feature: `git checkout -b my-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Submit a pull request.

## ⚡ License

Project licensed under **GPL v2**.
Created for security and research environments on FreeBSD.

---

## ❤️ Author

**Airbotz**
Developed by [@aleksander-haugas](https://github.com/aleksander-haugas)
FreeBSD Enthusiast & Network Security Developer.


