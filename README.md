# 🧠 Airbotz IDS

**Airbotz** es un sistema ligero de detección de intrusos (IDS) diseñado específicamente para **FreeBSD**, con integración nativa con el firewall **PF (Packet Filter)** y captura de tráfico mediante **pflog** y **tcpdump**.  
Su objetivo es detectar comportamientos anómalos en red en tiempo real, como *port scans*, *SYN floods*, *UDP floods* o *ICMP floods*, sin requerir dependencias externas ni kernel modules adicionales.

---

## 🚀 Características

- 📡 **Integración nativa con PF** mediante `pflog0`.
- ⚙️ **Parser eficiente en C** optimizado con `libpcap` y `pthread`.
- 🔍 Detección de:
  - Escaneos de puertos (portscan)
  - SYN floods
  - UDP floods
  - ICMP floods
- 📊 Sistema de estado persistente en `/var/db/airbotz/`.
- 🧩 Configuración por reglas (`airzox.conf`) con umbrales por evento.
- 🔥 Integración modular con `rules.c` para aplicar *bans*, *watchlists* o *acciones personalizadas*.
- 🧱 Pensado para entornos **FreeBSD Hardened** (sin dependencias no seguras).
- 🪶 Consumo extremadamente bajo (<5MB RAM en ejecución).

---

## 🧩 Requisitos

- **Sistema operativo:** FreeBSD 13.2+ / 14.x  
- **Dependencias:**  
```

libpcap
pthread

````
- **Firewall PF activado** con interfaz `pflog0` configurada:
```bash
echo 'pflog_enable="YES"' >> /etc/rc.conf
service pflog start
````

---

## ⚙️ Instalación desde GitHub

1. **Clonar el repositorio:**

   ```bash
   git clone https://github.com/aleksander-haugas/airbotz.git /usr/local/src/airbotz
   cd /usr/local/src/airbotz
   ```

2. **Compilar:**

   ```bash
   make
   ```

3. **Instalar binarios:**

   ```bash
   sudo make install
   ```

   Esto instalará:

   ```
   /usr/local/bin/airbotz
   /usr/local/etc/airzox.conf
   /var/db/airbotz/airbotz.dat
   /var/log/airbotz_alerts.json
   /var/log/airbotz.log
   ```

4. **Dar permisos mínimos:**

   ```bash
   sudo chown root:wheel /usr/local/bin/airbotz
   sudo chmod 755 /usr/local/bin/airbotz
   sudo mkdir -p /var/db/airbotz /var/log/airbotz
   sudo chmod 700 /var/db/airbotz
   ```

---

## 🔧 Configuración básica (`/usr/local/etc/airzox.conf`)

Ejemplo de configuración por evento:

```ini
# Servicio   Evento                Intentos   Tiempo(s)  Acción         Duración
sshd         ssh_failed_login      5           300        ban_temp       600
vsftpd       ftp_login_failed      6           600        ban_temp       900
pflog        portscan              15          60         log_only       0
nginx        sql_injection_attempt 10          60         ban_temp       0
```

Cada línea define:

```
servicio   tipo_evento   umbral_intentos   ventana_tiempo   acción   duración_ban
```

---

## ▶️ Ejecución

1. **Iniciar el servicio manualmente:**

   ```bash
   service airbotz start
   ```

2. **Ver alertas en tiempo real:**

   ```bash
   tail -f /var/log/airbotz_alerts.json
   ```

3. **Ver estado actual:**

   ```bash
   airbotz status
   ```


---

## 🧩 Integración con PF

Para capturar correctamente los paquetes en `pflog0`, asegúrate de tener reglas con `log` habilitado en `/etc/pf.conf`:

```pf
# Ejemplo básico
block in log all
pass in log on egress proto tcp to port 80
pass out all keep state
```

Luego recarga las reglas:

```bash
sudo pfctl -f /etc/pf.conf
```

---

## 🧠 Ejemplo de salida de alerta

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

## 🛠️ Desarrollo

Compilación en modo debug:

```bash
make clean
make DEBUG=1
```

Formatear código:

```bash
clang-format -i src/*.c include/*.h
```

---

## ⚡ Licencia

Proyecto bajo licencia **GPL v2**.
Creado para entornos de investigación y seguridad en FreeBSD.

---

## ❤️ Autor

**Airbotz**
Desarrollado por [@aleksander-haugas](https://github.com/aleksander-haugas)
FreeBSD Enthusiast.
