# NetGuard-CLI: HSE-Incident Detection Tool

A Python CLI application for real-time network traffic analysis and detection of HSE ransomware attack patterns. Monitors live traffic or replays `.pcap` files to identify data exfiltration, C2 beaconing, port scanning, and bandwidth spikes — with Deep Packet Inspection, composable traffic filters, and automatic PCAP forensic export.

---

## Overview

NetGuard-CLI detects attack patterns associated with ransomware operations, modelled on the 2021 HSE (Health Service Executive) Conti ransomware attack:

| Detection | What it catches | Severity |
|---|---|---|
| **Data Exfiltration** | Large outbound transfers to external IPs | HIGH |
| **C2 Beaconing** | Machine-regular communication intervals (any cadence) | HIGH |
| **Port Scanning** | Rapid multi-port enumeration on internal hosts | MEDIUM |
| **Traffic Spike** | Z-score bandwidth anomaly above rolling baseline | MEDIUM |

---

## Installation

### Linux (recommended path)

```bash
# Clone / download the project
cd netguard-cli

# Run the automated setup script — handles system deps, venv, pip, and setcap
chmod +x setup.sh
./setup.sh
```

The script will:
1. Install `libpcap-dev` via your distro's package manager
2. Create a Python virtual environment under `venv/`
3. Install all Python dependencies
4. Grant `cap_net_raw` to the venv Python binary so you can capture without `sudo`

Then activate the environment:
```bash
source venv/bin/activate
```

#### Manual Linux install

```bash
# Ubuntu / Debian
sudo apt-get install libpcap-dev python3-dev build-essential

# Fedora / RHEL / CentOS
sudo dnf install libpcap-devel python3-devel gcc

# Arch / Manjaro
sudo pacman -S libpcap python

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Packet capture privileges (Linux)

Live capture requires raw socket access. Two options:

**Option A — sudo (simplest)**
```bash
sudo python3 main.py --interface eth0
```

**Option B — setcap (no sudo at runtime, recommended)**
```bash
# Grant capability to the venv Python binary once
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

# Verify
getcap $(readlink -f $(which python3))
# Expected: python3 = cap_net_raw,cap_net_admin+eip

# Now run without sudo
python3 main.py --interface eth0
```

### Windows

```bash
pip install -r requirements.txt
# Run as Administrator for live capture
python main.py --interface "Ethernet"
```

### macOS

```bash
brew install libpcap
pip install -r requirements.txt
sudo python3 main.py --interface en0
```

---

## Quick Start

```bash
# List available interfaces
python3 main.py --list-interfaces

# Live capture on eth0
sudo python3 main.py --interface eth0

# Replay a pcap file (no root needed)
python3 main.py --pcap capture.pcap

# Live capture with BPF filter (only HTTPS traffic)
sudo python3 main.py --interface eth0 --bpf "tcp port 443"

# Auto-export pcap on HIGH alerts + filter to one subnet
sudo python3 main.py --interface eth0 --filter-ip 10.0.0.0/8 --export-pcap
```

---

## All Command-Line Arguments

```
Capture source:
  --interface, -i   Network interface for live capture (default: system default)
  --pcap, -p        Path to .pcap file for simulation/replay mode
  --list-interfaces List available interfaces and exit

Detection thresholds:
  --threshold, -t   Exfiltration threshold in MB (default: 1.0)
  --beacon-interval, -b  Reference beaconing interval in seconds (default: 5)
  --port-threshold  Unique ports to trigger port scan alert (default: 5)

Filtering:
  --bpf             BPF capture filter, e.g. "tcp port 80" (live capture only)
  --filter-ip CIDR  Only analyse traffic involving this CIDR range (repeatable)
  --filter-protocol PROTO  Only analyse this protocol, e.g. HTTP DNS TLS (repeatable)

PCAP forensics:
  --export-pcap     Auto-dump rolling packet buffer on every HIGH-severity alert
  --pcap-output-dir Directory for exported pcap files (default: forensics/)
```

### Filter examples

```bash
# Only analyse DNS traffic from the internal network
python3 main.py --pcap capture.pcap --filter-ip 192.168.0.0/16 --filter-protocol DNS

# Only watch HTTPS and TLS
sudo python3 main.py -i eth0 --filter-protocol TLS --filter-protocol HTTP

# Capture only TCP traffic at kernel level (BPF), then narrow further to one subnet
sudo python3 main.py -i eth0 --bpf "tcp" --filter-ip 10.0.0.0/8
```

---

## Architecture

```
netguard-cli/
├── main.py       Entry point, CLI parsing, orchestration, signal handling
├── sniffer.py    Packet capture (Scapy), DPI, queue-based dispatch, pcap export buffer
├── analyzer.py   Detection engine: exfiltration, beaconing, port scan, traffic spike
├── dpi.py        Deep Packet Inspection — protocol ID from payload bytes
├── filters.py    Composable traffic filter system (IP range, protocol, port, time)
├── logger.py     Thread-safe CSV logger + PcapExporter for Wireshark forensics
├── ui.py         Rich library live dashboard
├── test_alerts.py  Offline test suite (no network or root required)
├── setup.sh      Linux automated setup script
└── requirements.txt
```

### Module responsibilities

| Module | Responsibility |
|---|---|
| `sniffer.py` | Raw packet capture via Scapy; DPI-enriched `PacketInfo`; producer/consumer queue to prevent packet loss; rolling 1000-packet PCAP buffer |
| `dpi.py` | Stateless payload inspector — identifies HTTP, TLS, SSH, DNS, FTP, SMTP, RDP, mDNS, NTP by signature, falls back to port mapping |
| `filters.py` | BPF-style composable filters combinable with `&`, `\|`, `~` operators |
| `analyzer.py` | Four detection algorithms with alert deduplication/cooldown |
| `logger.py` | Thread-safe CSV append; `PcapExporter` dumps forensic captures to `forensics/` |
| `ui.py` | Live Rich dashboard: flows table (with DPI App column), alerts panel, statistics |
| `main.py` | Wires everything together; safe signal handling; privilege check with `setcap` hint |

---

## Detection Algorithms

### 1. Data Exfiltration
Sliding-window byte counter per `(source_ip, dest_ip)` pair. Fires when cumulative bytes to an **external** IP exceed the threshold within the window. Cooldown prevents alert spam; resets when traffic drops below threshold.

### 2. C2 Beaconing
Collects inter-packet timestamps for each `(internal → external)` pair. Fires when the **coefficient of variation** (CV = std\_dev / mean) of the last 8 intervals falls below 15% — machine-precise timing regardless of the actual interval value. Requires 6+ contact points to prevent false positives.

### 3. Port Scanning
Counts unique destination ports per `(source, dest)` pair within a rolling time window. Fires when the count exceeds the threshold.

### 4. Traffic Spike
Per-source 1-second bandwidth buckets. After 10 seconds of baseline history, fires when the current bucket's byte count is ≥ 3 standard deviations above the rolling mean (Z-score ≥ 3.0). 10-second cooldown between alerts.

---

## Deep Packet Inspection

The `dpi.py` module identifies the application-layer protocol from raw payload bytes:

| Protocol | Detection method |
|---|---|
| HTTP | Request verb (`GET`, `POST`, …) or `HTTP/` response prefix |
| TLS | TLS record byte `0x16/0x17` + version bytes `0x03 0x00–0x04` |
| SSH | `SSH-` banner prefix |
| DNS | UDP/TCP port 53 with valid payload |
| FTP | 3-digit status codes or `USER`/`RETR`/`STOR` commands |
| SMTP | `220`, `EHLO`, `MAIL FROM` signatures |
| RDP | TPKT header `0x03 0x00` |
| mDNS | UDP port 5353 |
| NTP | UDP port 123 with valid LI/VN/Mode byte |
| Others | Port-number fallback table (MySQL, PostgreSQL, Redis, MongoDB …) |

The identified protocol appears as the **App** column in the dashboard's flows table, colour-coded for quick scanning.

---

## Output

### Live Dashboard

```
+- Recent Network Flows --------+  +- Security Alerts --------+
| Time     Src IP        ...App |  | [HIGH] Data Exfiltration  |
| 14:22:01 192.168.1.100 ...TLS |  | 192.168.1.5 -> 5.5.5.5   |
| 14:22:01 192.168.1.100 ...DNS |  | [HIGH] C2 Beaconing ...   |
+-------------------------------+  +---------------------------+
Packets: 14,832 | Alerts: 3 | Runtime: 00:02:14 | Ctrl+C to stop
```

### CSV Log (`alerts_log.csv`)

| timestamp | alert_type | severity | description | source_ip | dest_ip | details |
|---|---|---|---|---|---|---|
| 2025-02-22T14:22:05 | Data Exfiltration | HIGH | 1.05 MB sent to external IP | 192.168.1.5 | 5.5.5.5 | {...} |

### Forensic PCAP (`forensics/`)

When `--export-pcap` is used, a `.pcap` file is written to `forensics/` on every HIGH-severity alert, named with a timestamp and alert type, e.g.:
```
forensics/capture_20250222_142205_Data_Exfiltration.pcap
```
Open directly in Wireshark for full packet analysis.

---

## Testing (no root required)

```bash
python3 test_alerts.py
```

Runs 6 offline tests that inject crafted `PacketInfo` objects directly into the detection engine and DPI module — no network interface or root privileges needed:

| Test | What it verifies |
|---|---|
| 1 | Data Exfiltration alert fires at 1 MB threshold |
| 2 | C2 Beaconing detected via CV at 10-second intervals |
| 3 | Port Scan fires after 6 unique ports |
| 4 | Traffic Spike detected via Z-score ≥ 3.0 |
| 5 | DPI correctly identifies 8 protocol signatures |
| 6 | Filter combinators (`&`, `\|`, `~`) accept/reject correctly |

---

## Security Considerations

- **Authorisation**: Only monitor networks you own or have explicit written permission to monitor. Unauthorised packet capture may violate laws.
- **Privilege model**: Prefer `setcap` over running the entire process as root to reduce the attack surface.
- **CSV log**: `alerts_log.csv` may contain sensitive IP addresses — secure it appropriately.
- **PCAP exports**: `forensics/*.pcap` files contain raw packet payloads — treat as sensitive.
- **False positives**: Detection uses statistical heuristics. Tune thresholds for your environment.

---

## Troubleshooting

### `Operation not permitted` on Linux
```bash
# Option 1 — sudo
sudo python3 main.py --interface eth0

# Option 2 — setcap (permanent, no sudo at runtime)
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

### No packets captured
```bash
# Confirm interface name
ip link show
python3 main.py --list-interfaces

# Check you have the right interface (try 'lo' for loopback testing)
sudo python3 main.py --interface lo
```

### `ModuleNotFoundError: scapy`
```bash
pip install -r requirements.txt
# If using a venv, ensure it is activated first
source venv/bin/activate
```

### `ImportError: libpcap.so` on Linux
```bash
sudo apt-get install libpcap-dev    # Debian/Ubuntu
sudo dnf install libpcap-devel      # Fedora/RHEL
```

---

## References

- HSE Ransomware Attack (2021) — Health Service Executive of Ireland
- Conti Ransomware Group — Threat actor behind the HSE attack
- Cobalt Strike — C2 framework used during the attack
- RFC 1918 — Private address space used for internal IP classification
- RFC 5737 — TEST-NET address ranges used in documentation and test code

---

## Disclaimer

For authorised security testing and incident detection only. Unauthorised network monitoring may violate applicable laws and regulations.
