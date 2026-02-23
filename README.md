# NetGuard-CLI: HSE-Incident Detection Tool

A Python CLI application for real-time network traffic analysis and detection of HSE ransomware attack patterns. Monitors live traffic or replays `.pcap` files to identify data exfiltration, C2 beaconing, port scanning, and bandwidth spikes — with Deep Packet Inspection, composable traffic filters, and automatic PCAP forensic export.

---

## Table of Contents

1. [Overview](#overview)
2. [HSE Attack Context](#hse-attack-context)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [All CLI Arguments](#all-cli-arguments)
6. [Triggering Alerts](#triggering-alerts)
7. [Architecture](#architecture)
8. [Detection Algorithms](#detection-algorithms)
9. [Deep Packet Inspection](#deep-packet-inspection)
10. [Traffic Filters](#traffic-filters)
11. [Output](#output)
12. [Testing](#testing)
13. [Security Considerations](#security-considerations)
14. [Troubleshooting](#troubleshooting)
15. [References](#references)

---

## Overview

NetGuard-CLI detects four attack patterns associated with ransomware operations, modelled on the 2021 HSE Conti ransomware attack:

| Detection | What it catches | Severity |
|---|---|---|
| **Data Exfiltration** | Large cumulative outbound transfers to external IPs | HIGH |
| **C2 Beaconing** | Machine-regular communication intervals at any cadence | HIGH |
| **Port Scanning** | Rapid multi-port enumeration on internal hosts | MEDIUM |
| **Traffic Spike** | Z-score bandwidth anomaly above a rolling baseline | MEDIUM |

---

## HSE Attack Context

### The 2021 HSE Ransomware Attack

In May 2021 the Health Service Executive (HSE) of Ireland suffered a devastating ransomware attack orchestrated by the Conti group. Healthcare services across the country were disrupted and approximately **700 GB of sensitive patient data** was exfiltrated before ransomware was deployed.

### Attack Stages Detected by NetGuard-CLI

#### Stage 1 — Data Exfiltration
Attackers exfiltrated ~700 GB of healthcare data before detonating the ransomware. NetGuard-CLI detects this by:
- Tracking cumulative bytes per `(internal IP → external IP)` pair within a sliding time window
- Alerting when any external destination receives more than the configured threshold (default 1 MB) within 30 seconds
- Using alert cooldown to avoid spam while the transfer is ongoing

#### Stage 2 — C2 Beaconing
Conti used Cobalt Strike C2 infrastructure to maintain persistent access. NetGuard-CLI detects this by:
- Collecting inter-packet gap timestamps for every `(internal → external)` pair
- Computing the **coefficient of variation** (CV = std_dev / mean) over the last 8 gaps
- Firing when CV ≤ 0.15 (≤15% variation) — machine-precise timing that no human browsing pattern produces
- Works at **any interval** (30 s, 5 min, 1 hr) — not just a single configured value

#### Stage 3 — Port Scanning
Reconnaissance and lateral movement involved rapid port enumeration. NetGuard-CLI detects this by:
- Counting unique destination ports per `(source, dest)` pair within a rolling 10-second window
- Alerting when a single source accesses more than 5 ports (configurable) on the same host

#### Stage 4 — Traffic Spike (Lateral Movement / Bulk Copy)
Rapid internal data movement before encryption shows up as bandwidth bursts. NetGuard-CLI detects this by:
- Maintaining 1-second byte-count buckets per source IP over a 60-second rolling window
- Computing a Z-score on the current second vs the historical baseline
- Alerting when Z-score ≥ 3.0 (more than 3 standard deviations above normal)

---

## Installation

### Linux (recommended path)

```bash
# Run the automated setup script
# Handles: libpcap install, venv creation, pip install, setcap privilege grant
chmod +x setup.sh
./setup.sh

# Activate the virtual environment
source venv/bin/activate
```

#### Manual Linux install

```bash
# Ubuntu / Debian / Mint
sudo apt-get install libpcap-dev python3-dev build-essential

# Fedora / RHEL / CentOS
sudo dnf install libpcap-devel python3-devel gcc

# Arch / Manjaro
sudo pacman -S libpcap python

# Install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Packet capture privileges (Linux)

Live capture requires raw socket access. Choose one option:

**Option A — sudo (simplest)**
```bash
sudo python3 main.py --interface eth0
```

**Option B — setcap (no sudo at runtime, recommended)**
```bash
# Grant the capability once
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

# Verify
getcap $(readlink -f $(which python3))
# Expected output: python3 = cap_net_raw,cap_net_admin+eip

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
# Live capture on eth0 (Linux)
sudo python3 main.py --interface eth0

# Replay a pcap file — no root needed
python3 main.py --pcap capture.pcap

# Lower thresholds for a sensitive environment
sudo python3 main.py --interface eth0 --threshold 0.5 --port-threshold 3

# Run offline tests — no network or root required
python3 tests/test_alerts.py
```

---

## All CLI Arguments

```
  --interface, -i   Network interface for live capture
  --pcap, -p        Path to .pcap file for simulation mode
  --threshold, -t   Exfiltration alert threshold in MB  (default: 1.0)
  --port-threshold  Unique ports to trigger port scan   (default: 5)
```

---

## Triggering Alerts

### Option 1 — Offline test script (no root, no network)

```bash
python3 tests/test_alerts.py
```

Injects crafted packets directly into the engine. Fires all 6 alert types in ~15 seconds:

| Test | Alert | How it's triggered |
|---|---|---|
| 1 | Data Exfiltration | 12 × 100 KB packets to the same external IP cross the 1 MB threshold |
| 2 | C2 Beaconing | 8 packets exactly 10 s apart produce CV = 0.00 |
| 3 | Port Scan | Hits ports 22, 80, 443, 3389, 8080, 8443, 21, 25 in 4 seconds |
| 4 | Traffic Spike | 15 s of ~10 KB/s baseline then a 500 KB burst (Z ≈ 97) |
| 5 | DPI | Verifies HTTP / TLS / SSH / DNS / RDP payload recognition |
| 6 | Filters | Verifies `&`, `\|`, `~` filter combinators |

### Option 2 — Real traffic (requires root / setcap)

Start the tool first in one terminal:
```bash
sudo python3 main.py --interface eth0
```

Then run one of these in a second terminal:

#### Data Exfiltration — send >1 MB to an external IP
```bash
# Send 2 MB via curl
dd if=/dev/urandom bs=1M count=2 | curl -s -X POST --data-binary @- http://httpbin.org/post
```

#### C2 Beaconing — contact the same external IP on a fixed interval
```bash
# Contact example.com every 10 seconds (needs 6+ repetitions to build the pattern)
for i in $(seq 1 10); do
    curl -s https://example.com -o /dev/null
    sleep 10
done
```

#### Port Scan — hit multiple ports on an internal host
```bash
# With nmap
nmap -p 22,80,443,3389,8080,8443,21,25 192.168.1.x

# Without nmap — bash TCP probes
for port in 22 80 443 3389 8080 8443 21 25; do
    (echo >/dev/tcp/192.168.1.x/$port) 2>/dev/null &
done
```

#### Traffic Spike — burst after idle
```bash
# Build a baseline for 15 s, then blast 5 MB
sleep 15 && dd if=/dev/urandom bs=1M count=5 | nc -q1 8.8.8.8 80
```

### Option 3 — Replay a real malware pcap

```bash
# No root required for pcap replay
python3 main.py --pcap malware_sample.pcap
```

Free pcap sources with real attack traffic:
- https://www.malware-traffic-analysis.net
- https://github.com/markofu/pcaps
- https://www.netresec.com/?page=PcapFiles

---

## Architecture

```
netguard-cli/
├── src/
│   ├── __init__.py
│   ├── analyzer.py      Detection engine: exfiltration, beaconing, port scan, traffic spike
│   ├── dpi.py           Deep Packet Inspection — protocol ID from payload bytes
│   ├── filters.py       Composable traffic filter system (IP range, protocol, port, time)
│   ├── logger.py        Thread-safe CSV logger + PcapExporter for Wireshark forensics
│   ├── sniffer.py       Packet capture (Scapy), DPI, queue-based dispatch, pcap export buffer
│   └── ui.py            Rich library live dashboard
├── tests/
│   ├── __init__.py
│   └── test_alerts.py   Offline test suite — no network or root required
├── main.py              Entry point, CLI parsing, orchestration, signal handling
├── setup.sh             Linux automated setup script
└── requirements.txt
```

### Module responsibilities

| Module | Responsibility |
|---|---|
| `src/sniffer.py` | Raw capture via Scapy; DPI-enriched `PacketInfo`; producer/consumer queue (10k capacity) to prevent packet loss; rolling 1000-packet PCAP buffer |
| `src/dpi.py` | Stateless payload inspector — identifies 10+ protocols by signature, falls back to well-known port table |
| `src/filters.py` | BPF-style composable filters combined with `&` (AND), `\|` (OR), `~` (NOT) |
| `src/analyzer.py` | Four detection algorithms each with independent alert cooldown/deduplication |
| `src/logger.py` | Thread-safe CSV append (reentrant lock); `PcapExporter` writes timestamped `.pcap` files |
| `src/ui.py` | Live Rich dashboard: colour-coded flows table (App column), alerts panel, statistics breakdown |
| `main.py` | Orchestration; safe SIGINT/SIGTERM handling; privilege check with `setcap` guidance |

### Data flow

```
Network interface / pcap file
        |
  src/sniffer.py  ──(Scapy sniff loop)──> queue ──> consumer thread
        |                                                   |
  src/dpi.py                                          PacketInfo
   (protocol ID)                                           |
                                                  src/filters.py  (drop?)
                                                           |
                                                  src/analyzer.py
                                              (4 detection algorithms)
                                                           |
                                               ┌───────────┴───────────┐
                                            alerts                  flows
                                               |                       |
                                        src/logger.py            src/ui.py
                                      (CSV + PCAP export)     (Rich dashboard)
```

---

## Detection Algorithms

### 1. Data Exfiltration

Sliding-window cumulative byte counter per `(source_ip, dest_ip)` pair.

- Only monitors **internal → external** traffic
- Fires once when total bytes in the window cross the threshold
- Cooldown = exfiltration window (30 s by default); resets if traffic drops below threshold so the next surge fires a fresh alert
- Alert includes total bytes, MB transferred, and the time window

### 2. C2 Beaconing

Statistical regularity detector on inter-contact timestamps.

- Records every contact timestamp for each `(internal → external)` pair
- Requires 6+ contacts (5 intervals) before evaluating
- Computes **CV = std\_dev / mean** over the last 8 intervals
- Fires when CV ≤ 0.15 and avg interval ≥ 2 s (to ignore legitimate high-frequency traffic)
- Cooldown = avg\_interval × number\_of\_intervals\_analysed
- Alert includes avg interval, std dev, CV, and beacon count

### 3. Port Scanning

Rolling unique-port counter per `(source, dest)` pair.

- Tracks port → last-seen-timestamp in a sliding window
- Fires when unique ports in the window exceed the threshold
- No cooldown — each new port after threshold escalates the alert count
- Alert includes all scanned port numbers (up to 20 listed)

### 4. Traffic Spike

Z-score anomaly detection on per-second bandwidth buckets.

- Accumulates bytes into integer-second buckets per source IP
- Maintains a 60-second rolling history; requires 10 completed seconds before alerting
- Z-score = (current\_second\_bytes − mean) / std\_dev
- Fires when Z-score ≥ 3.0 (≈ 99.7th percentile under normal distribution)
- 10-second cooldown between alerts per source
- Alert includes current rate, baseline mean, std dev, and Z-score

---

## Deep Packet Inspection

`src/dpi.py` identifies the application-layer protocol from raw payload bytes — **independent of port numbers**. This catches malware that uses non-standard ports.

Detection order: payload signatures first, port fallback second.

| Protocol | Detection method |
|---|---|
| HTTP | Request verb (`GET`, `POST`, `PUT`, …) or `HTTP/` response line |
| TLS / HTTPS | TLS record type byte `0x14–0x17` + version `0x03 0x00–0x04` |
| SSH | `SSH-` banner prefix |
| DNS | UDP/TCP port 53 with payload present |
| FTP | 3-digit status codes or `USER`/`RETR`/`STOR` client commands |
| SMTP | `220`, `EHLO`, `HELO`, `MAIL FROM` signatures |
| RDP | TPKT header `0x03 0x00` |
| mDNS | UDP port 5353 |
| NTP | UDP port 123 with valid LI/VN/Mode byte |
| Others | Port fallback table: MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017), RDP (3389), … |

The identified protocol appears as the colour-coded **App** column in the flows table:

| Colour | Protocols |
|---|---|
| Green | HTTP |
| Cyan | TLS / HTTPS |
| Yellow | DNS |
| Red | SSH, RDP |
| Magenta | FTP |
| Blue | SMTP |
| Dim | Unknown |

---

## Traffic Filters

`src/filters.py` provides a composable BPF-style filter system. Filters can be combined with Python operators:

| Operator | Meaning | Example |
|---|---|---|
| `&` | AND — both must match | `IPRangeFilter("10.0.0.0/8") & ProtocolFilter("DNS")` |
| `\|` | OR — either must match | `ProtocolFilter("HTTP") \| ProtocolFilter("TLS")` |
| `~` | NOT — invert the filter | `~ProtocolFilter("DNS")` |

### Available filters

| Filter | Description |
|---|---|
| `IPRangeFilter("10.0.0.0/8")` | Match if source or destination IP is in the CIDR range |
| `ProtocolFilter("HTTP", "TLS")` | Match transport or DPI-identified app protocol |
| `PortFilter(80, 443)` | Match if source or destination port is in the set |
| `TimestampFilter(start=t0, end=t1)` | Match packets within a Unix-timestamp range |
| `MinSizeFilter(1024)` | Match packets with payload ≥ N bytes |
| `AcceptAllFilter()` | Pass-through — accepts every packet |


---

## Output

### Live Dashboard

```
+-------- Recent Network Flows -----------+  +------- Security Alerts --------+
| Time     Src IP          App    Port    |  | [14:22:05] [HIGH]               |
| 14:22:05 192.168.1.100   TLS    443     |  | Data Exfiltration:              |
| 14:22:04 192.168.1.100   DNS    53      |  | 1.05 MB sent to external IP     |
| 14:22:03 192.168.1.200   HTTP   80      |  | 192.168.1.5 -> 203.0.113.42     |
+-----------------------------------------+  | [14:21:55] [HIGH]               |
                                             | C2 Beaconing: ~10.0s (CV=0.00)  |
+-------- Alert Statistics ---------------+  +---------------------------------+
| Total Alerts          3                 |
| By Type:                                |
|   Data Exfiltration   1   33.3%         |
|   C2 Beaconing        1   33.3%         |
|   Port Scan           1   33.3%         |
| By Severity:                            |
|   HIGH                2   66.7%         |
|   MEDIUM              1   33.3%         |
+-----------------------------------------+
Packets: 14,832 | Alerts: 3 | Runtime: 00:02:14 | Press Ctrl+C to stop
```

### CSV Log — `alerts_log.csv`

All alerts are appended to `alerts_log.csv` with these columns:

| Column | Example |
|---|---|
| `timestamp` | `2025-02-22T14:22:05.123` |
| `alert_type` | `Data Exfiltration` |
| `severity` | `HIGH` |
| `description` | `Large data transfer detected: 1.05 MB sent to external IP` |
| `source_ip` | `192.168.1.5` |
| `dest_ip` | `203.0.113.42` |
| `details` | `{'total_bytes': 1100000, 'mb_transferred': 1.05, ...}` |

### Forensic PCAP — `forensics/`

When `--export-pcap` is set, the rolling 1000-packet buffer is written to disk on every HIGH-severity alert:

```
forensics/capture_20250222_142205_Data_Exfiltration.pcap
forensics/capture_20250222_142312_C2_Beaconing.pcap
```

Open in Wireshark for full protocol dissection and packet-level forensics.

---

## Testing

Run the offline test suite — **no network interface, no root, no pcap file needed**:

```bash
python3 tests/test_alerts.py
```

| Test | Alert type | Pass condition |
|---|---|---|
| 1 | Data Exfiltration | Fires on packet 11 of 12 (crosses 1 MB); packet 12 is silenced by cooldown |
| 2 | C2 Beaconing | Fires on beacon 6 (CV = 0.00); beacons 7–8 inside cooldown window |
| 3 | Port Scan | Fires at port 6, escalates at 7 and 8 |
| 4 | Traffic Spike | Fires after 15 s baseline when 500 KB burst gives Z ≈ 97 |
| 5 | DPI | 8 protocol signatures all correctly identified |
| 6 | Filters | 10 accept/reject decisions correct with `&`, `\|`, `~` combinators |

---

## Security Considerations

- **Authorisation** — Only monitor networks you own or have explicit written permission to monitor. Unauthorised packet capture may violate laws and regulations.
- **Privilege model** — Prefer `setcap cap_net_raw` over running the full process as root. This minimises the attack surface while still allowing packet capture.
- **CSV log** — `alerts_log.csv` may contain IP addresses and flow metadata. Apply appropriate file permissions.
- **PCAP exports** — Files in `forensics/` contain raw packet payloads and may include credentials, session tokens, or other sensitive data. Treat accordingly.
- **False positives** — All detection is heuristic. Tune thresholds (`--threshold`, `--port-threshold`) for your network's baseline behaviour.
- **Encrypted traffic** — TLS/HTTPS payload contents are not analysed; DPI only identifies the protocol from the handshake header.

---

## Troubleshooting

### `Operation not permitted` / `Permission denied` on Linux
```bash
# Option 1 — run with sudo
sudo python3 main.py --interface eth0

# Option 2 — grant capability (no sudo at runtime, permanent)
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

# Or run the setup script which handles this automatically
./setup.sh
```

### No packets captured
```bash
# List available interfaces
ip link show
python3 -c "from scapy.all import get_if_list; print(get_if_list())"

# Try the loopback interface for basic connectivity testing
sudo python3 main.py --interface lo

# Verify traffic is present on the interface
sudo tcpdump -i eth0 -c 5
```

### Alerts not firing
```bash
# Run the offline test suite to confirm detection logic works
python3 tests/test_alerts.py

# Lower thresholds for testing
python3 main.py --pcap capture.pcap --threshold 0.1 --port-threshold 3
```

### `ModuleNotFoundError: No module named 'scapy'`
```bash
# Activate the virtual environment first
source venv/bin/activate
pip install -r requirements.txt
```

### `ImportError: libpcap.so` on Linux
```bash
sudo apt-get install libpcap-dev    # Debian / Ubuntu / Mint
sudo dnf install libpcap-devel      # Fedora / RHEL / CentOS
sudo pacman -S libpcap              # Arch / Manjaro
```

### Terminal looks broken after Ctrl+C
The Rich `Live` display restores the terminal on clean exit. If it gets stuck:
```bash
reset    # restore terminal to normal state
```

---

## References

- [HSE Ransomware Attack (2021)](https://www.hse.ie/eng/services/publications/conti-cyber-attack-on-the-hse-full-report.pdf) — Official HSE post-incident report
- [Conti Ransomware Group](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a) — CISA Advisory AA21-265A
- [Cobalt Strike](https://www.cobaltstrike.com/) — C2 framework used during the attack
- [RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918) — Private address space (internal IP classification)
- [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) — TEST-NET ranges used in test code (`203.0.113.0/24`, `198.51.100.0/24`)
- [Scapy](https://scapy.net/) — Packet manipulation library
- [Rich](https://github.com/Textualize/rich) — Terminal formatting library

---

## Disclaimer

This tool is provided for authorised security testing and incident detection only. Unauthorised network monitoring may violate applicable laws and regulations in your jurisdiction. Always obtain written permission before monitoring traffic on any network you do not own.
