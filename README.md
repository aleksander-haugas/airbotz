# Airbotz – Intrusion Detection & Prevention System for FreeBSD

![Airbotz](https://img.shields.io/badge/Status-Active-brightgreen) ![Language C](https://img.shields.io/badge/Language-C-blue)

**Airbotz** is an **Intrusion Detection & Prevention System (IDS/IPS)** specifically designed for **FreeBSD**, optimized to work with **PF (Packet Filter)**, protecting servers from network attacks, brute force attempts, and malicious activity across SSH, FTP, Nginx, Minecraft services...etc.

---

## 🚀 Key Features

* Native integration with **PF/pflog** for real-time protection.
* Detection of **port scans, SYN/UDP floods, ICMP floods**, and other network anomalies.
* Service-level protection:
  * **SSH / SFTP** – failed logins, invalid users, suspicious disconnects  
  * **FTP** – failed logins, anonymous access, suspicious uploads/downloads  
  * **Nginx / Web** – brute force, SQL injection, XSS, directory scanning, data exfiltration  
  * **Minecraft** – login failures, chat spam, block flood attempts
* **Configurable rule system** with thresholds, time windows, action types, and ban durations.
* **Temporary and permanent ban management** with automatic escalation.
* **Smart counters** to prevent false positives and detect repeated offenders.
* Detailed logs stored at `/var/log/airbotz.log`.
* **Extremely low resource usage** (<10MB RAM, near-zero CPU idle).

---

## 🧩 Requirements

- **Operating System:** FreeBSD 13.2+ / 14.x  
- **Dependencies:**
```bash
libpcap
pthread
```

* **PF firewall** enabled with `pflog0` configured:

```bash
echo 'pflog_enable="YES"' >> /etc/rc.conf
service pflog start
```

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

Example rule configuration:

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
* `alert_only` – Log alert only
* `log_only` – Passive logging only
* `watchlist` – Track without banning

---

## ▶️ Usage

Start the service manually:

```bash
service airbotz start
```

View real-time alerts:

```bash
tail -f /var/log/airbotz_alerts.json
```

Check current status:

```bash
airbotz status
```

Stop or restart:

```bash
service airbotz stop
service airbotz restart
```

---

## 🧩 System Integration (rc.d)

Enable automatic startup at boot:

```bash
echo 'airbotz_enable="YES"' >> /etc/rc.conf
```

Manage the daemon:

```bash
service airbotz start     # Start Airbotz
service airbotz stop      # Stop Airbotz
service airbotz restart   # Restart the daemon
service airbotz status    # Show current status
```

Verify Airbotz is running:

```bash
ps aux | grep airbotz
```

Example:

```
root  9928  0.0  0.0  26000  10400  -  Ss   08:01   0:01.00  airbotz
```

---

## 🧱 PF Table Integration

Airbotz maintains two PF tables for banned IPs:

| Type           | Table name     | Description                               |
| -------------- | -------------- | ----------------------------------------- |
| Temporary bans | `airbotz_temp` | Automatically expires after rule duration |
| Permanent bans | `airbotz_perm` | Persistent until manually removed         |

### 1️⃣ Declare the tables in `/etc/pf.conf`

```pf
table <airbotz_temp> persist
table <airbotz_perm> persist
```

### 2️⃣ Add rules to block banned IPs

```pf
block in quick from <airbotz_temp> to any
block in quick from <airbotz_perm> to any
pass out all keep state
```

### 3️⃣ Reload PF rules

```bash
pfctl -f /etc/pf.conf
pfctl -t airbotz_temp -T show
pfctl -t airbotz_perm -T show
```

When Airbotz bans an IP, you’ll see:

```
# pfctl -t airbotz_temp -T show
185.237.102.51
176.67.81.228
```

Temporary bans expire automatically, and PF tables are synchronized on startup.

---

## 🧹 Manual Maintenance

Remove all temporary bans:

```bash
pfctl -t airbotz_temp -T flush
```

Remove a specific IP:

```bash
pfctl -t airbotz_perm -T delete 203.0.113.25
```

Clear both tables:

```bash
pfctl -t airbotz_temp -T flush
pfctl -t airbotz_perm -T flush
```

---

## ⚡ Escalation Logic

* If an IP repeatedly reaches the threshold, **temporary bans automatically escalate to permanent**.
* **Permanent bans override** any temporary ban attempts.
* Escalation history is tracked through smart counters.

---

## 🧠 Example Alert Output

```json
{
  "timestamp": "2025-10-24T18:25:43+0000",
  "service": "pflog",
  "event": "portscan",
  "ip": "10.1.10.200",
  "info": "portscan detected: 15 unique ports (window=60s)"
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

## 🤝 Contributing

1. Fork the repository.
2. Create your feature branch: `git checkout -b my-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push and open a Pull Request.

---

## ⚖️ License

Project licensed under **GPL v2**.
Created for security and research environments on FreeBSD.

---

## ❤️ Author

**Airbotz**
Developed by [@aleksander-haugas](https://github.com/aleksander-haugas)
FreeBSD Enthusiast & Developer.

---
