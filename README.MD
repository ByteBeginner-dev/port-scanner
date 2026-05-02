# Python Network Scanning Scripts

A collection of Python scripts for network reconnaissance — port scanning, host discovery, and host reachability checks.

> ⚠️ **Legal Notice:** Use these tools only on networks and systems you own or have explicit permission to test.

---

## Scripts

### `open_scan.py` — Basic Port Scanner
Simple multithreaded TCP port scanner.

```bash
python open_scan.py
```

### `app.py` — Port Scanner with Nmap Integration
Extends `open_scan.py` with IP validation and optional Nmap service detection on discovered open ports.

```bash
python app.py
```

### `app3.py` — Optimized Multi-Process Scanner
High-performance scanner using multiprocessing + multithreading with configurable process/thread counts.

```bash
python app3.py
```

### `app4.py` — Optimized Scanner with Logging
Same as `app3.py` but replaces print statements with Python's `logging` module and uses `ipaddress` for stricter IP validation.

```bash
python app4.py
```

### `active_devices.py` — ARP Network Scanner
Discovers all active devices on the local network using ARP broadcast packets.

```bash
python active_devices.py
```

### `ping.py` — SYN Ping (Host Reachability)
Sends TCP SYN packets to common ports to determine if a host is online, bypassing ICMP filters.

```bash
python ping.py
```

---

## Scan Types (port scanners)

| Choice | Description         | Ports         |
|--------|---------------------|---------------|
| 1      | Basic Scan          | 12 common ports |
| 2      | Top 1000 Ports      | 1–1000        |
| 3      | Full Scan           | 1–65535       |

---

## Requirements

```bash
pip install scapy netifaces
```

- `scapy` — required by `active_devices.py` and `ping.py`
- `netifaces` — required by `active_devices.py`
- `nmap` — must be installed on the system and in PATH for Nmap integration in `app.py`, `app3.py`, `app4.py`

> `active_devices.py` and `ping.py` require **root/administrator privileges** to send raw packets.

---

## License

See [LICENSE](LICENSE).
