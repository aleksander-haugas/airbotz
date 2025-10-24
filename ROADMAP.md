# 🗺️ Airbotz Roadmap

This document outlines the **development roadmap** for **Airbotz**, detailing planned features, improvements, and future goals for the project.

---

## 🏁 Current Status – v0.1.0 (beta)

- ✅ Core IDS/IPS engine written in C  
- ✅ PF and pflog0 integration  
- ✅ Multi-service rule system (SSH, FTP, Nginx, Minecraft)  
- ✅ Real-time JSON logging and human-readable logs  
- ✅ Temporary and permanent ban management via PF tables  
- ✅ rc.d service control and automatic startup  
- ✅ Optimized for ultra-low CPU and memory usage  

---

## 🧩 Phase 1 – Stability & Monitoring (v1.1.x)

**Goal:** Improve reliability, transparency, and administrative control.

**Planned Tasks:**
- [ ] Add `airbotz status` command to show:
  - Active bans (temporary/permanent)
  - Service rules loaded
  - Recent alert statistics  
- [ ] Implement automatic cleanup of old log files (`logrotate` integration)  
- [ ] Improve error handling and recovery on PF reloads  
- [ ] Add verbose and quiet logging modes  
- [ ] Introduce `airbotz.conf.d/` include directory for modular rule configs  

---

## ⚙️ Phase 2 – Performance & Data Management (v1.2.x)

**Goal:** Enhance performance and provide structured data access.

**Planned Tasks:**
- [ ] Implement an in-memory cache for faster lookups of offenders  
- [ ] Add SQLite or JSON DB backend for tracking repeated offenders across reboots  
- [ ] Add CLI option: `--stats` to output JSON-formatted summary data  
- [ ] Enable partial reloads (`airbotz reload`) without full restart  
- [ ] Add support for concurrent packet processing threads (multi-core scalability)  

---

## 🌐 Phase 3 – Distributed Protection (v1.3.x)

**Goal:** Share intelligence between multiple FreeBSD servers.

**Planned Tasks:**
- [ ] Create **Airbotz Sync Protocol (ASP)** for peer-to-peer sync over TCP/SSL  
- [ ] Implement optional **master node** that aggregates alerts and pushes bans  
- [ ] Secure node authentication using pre-shared keys or certificates  
- [ ] Add configuration section:
```ini
[cluster]
mode = peer
peers = 10.0.0.2, 10.0.0.3
sync_interval = 300
```

* [ ] Option to disable network sync for standalone installations

---

## 🧠 Phase 4 – Smart Detection (v1.4.x)

**Goal:** Introduce adaptive and heuristic-based analysis.

**Planned Tasks:**

* [ ] Add **behavioral pattern learning** for detecting new attack types
* [ ] Integrate simple anomaly scoring system:

```
score = failed_logins * 2 + port_scans * 3 + icmp_floods * 1
```
* [ ] Configurable “learning mode” to collect metrics before enforcing bans
* [ ] Add optional **AI-assisted log correlation** via external analyzer (Python/PHP bridge)
* [ ] Integrate detection of multi-vector attacks (port scan + web flood combo)

---

## 🧰 Phase 5 – Web Dashboard & API (v1.5.x)

**Goal:** Provide real-time visualization and management.

**Planned Tasks:**

* [ ] Develop a **REST API** to expose:

  * Logs
  * Bans
  * Alerts
* [ ] Build a **web dashboard** in lightweight HTML/JS:

  * Real-time charts using WebSocket or SSE
  * Ban/unban controls
  * Service statistics and history
* [ ] Create `airbotzd` daemon that provides data to dashboard securely
* [ ] Add role-based authentication for web access

---

## 🔒 Phase 6 – Advanced Security & Compliance (v1.6.x)

**Goal:** Harden Airbotz for production and security certification.

**Planned Tasks:**

* [ ] Implement secure memory management and audit logging
* [ ] Add digital signature verification for rules and config files
* [ ] Optional encrypted storage for IP reputation database
* [ ] Introduce audit logs compatible with SIEM tools
* [ ] Perform independent security code audit and fuzz testing

---

## 🧩 Phase 7 – Extended Integrations (v2.0.x)

**Goal:** Expand ecosystem support and flexibility.

**Planned Tasks:**

* [ ] Integrate with **syslog**, **fail2ban**, and **suricata** for cooperative defense
* [ ] Allow rule import/export in JSON/YAML formats
* [ ] Add plugin system for external analyzers (C or Python modules)
* [ ] Optional export to **ElasticSearch / Loki / Grafana**
* [ ] Native support for jails and bhyve virtual interfaces

---

## 🧠 Future Ideas (Experimental)

* [ ] Machine-learning threat classifier (Naive Bayes / kNN)
* [ ] Passive fingerprinting of attackers (OS and device signatures)
* [ ] Integration with YARA or ClamAV for payload analysis
* [ ] Threat-sharing API (OpenCTI or MISP integration)
* [ ] Adaptive throttling of suspected IPs instead of full blocking

---

## 🧭 Development Priorities

| Priority  | Category     | Description                                        |
| --------- | ------------ | -------------------------------------------------- |
| 🟥 High   | Stability    | Ensure PF sync and logs remain reliable under load |
| 🟧 Medium | Visibility   | Expose more runtime info for administrators        |
| 🟨 Normal | Performance  | Optimize C structures and reduce syscalls          |
| 🟩 Low    | Experimental | AI-based and distributed features                  |

---

## 📅 Timeline Overview

| Quarter | Milestone                        | Version     |
| ------- | -------------------------------- | ----------- |
| Q4 2025 | Stability & Monitoring           | v1.1        |
| Q1 2026 | Performance & Data Layer         | v1.2        |
| Q2 2026 | Distributed Protection           | v1.3        |
| Q3 2026 | Smart Detection                  | v1.4        |
| Q4 2026 | Web Dashboard                    | v1.5        |
| 2027+   | Advanced Security & Integrations | v1.6 – v2.0 |

---

## ❤️ Contribution Notes

If you want to contribute to any of these milestones:

1. Open an issue referencing the **phase number and feature name**.
2. Discuss implementation details before coding.
3. Submit a PR targeting the next active milestone branch.

Example:

```
[Feature Request] Phase 2 – Add SQLite backend for IP tracking
```

---

**Maintained by:** [@aleksander-haugas](https://github.com/aleksander-haugas)
**Platform:** FreeBSD
**License:** GPL v2
**Project goal:** A lightweight, transparent, and adaptive IDS for BSD systems.

---
