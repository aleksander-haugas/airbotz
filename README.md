# 🧠 Airbotz IDS

**Airbotz** is a lightweight Intrusion Detection System (IDS) designed specifically for **FreeBSD**, with native integration into the **PF (Packet Filter)** firewall and traffic capture through **pflog** and **tcpdump**.  
Its goal is to detect abnormal network behavior in real time — such as *port scans*, *SYN floods*, *UDP floods*, or *ICMP floods* — without requiring external dependencies or additional kernel modules.

---

## 🚀 Features

- 📡 **Native PF integration** through `pflog0`.
- ⚙️ **High-performance C parser**, optimized with `libpcap` and `pthread`.
- 🔍 Detection of:
  - Port scans
  - SYN floods
  - UDP floods
  - ICMP floods
- 📊 Persistent state tracking in `/var/db/airbotz/`.
- 🧩 Rule-based configuration (`airzox.conf`) with per-event thresholds.
- 🔥 Modular integration via `rules.c` for applying *bans*, *watchlists*, or *custom actions*.
- 🧱 Designed for **FreeBSD Hardened** environments (no unsafe dependencies).
- 🪶 Extremely low resource usage (<5MB RAM while running).

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
   sudo make install
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
   sudo chown root:wheel /usr/local/bin/airbotz
   sudo chmod 755 /usr/local/bin/airbotz
   sudo mkdir -p /var/db/airbotz /var/log/airbotz
   sudo chmod 700 /var/db/airbotz
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
sudo pfctl -f /etc/pf.conf
```

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

## ⚡ License

Project licensed under **GPL v2**.
Created for security and research environments on FreeBSD.

---

## ❤️ Author

**Airbotz**
Developed by [@aleksander-haugas](https://github.com/aleksander-haugas)
FreeBSD Enthusiast & Network Security Developer.


