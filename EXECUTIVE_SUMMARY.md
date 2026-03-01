# NetGuard-CLI: Data Flow (4 Steps)

This document summarizes how the HSE Ransomware detection tool processes network traffic from capture to alert. Use it to explain the project in an oral exam.

---

## 1. Capture

**Where:** `sniffer.py` — `NetworkSniffer` (live interface or pcap file)

Raw network frames are collected from either:
- A **live network interface** (e.g. eth0), or  
- A **pcap file** (simulation/replay).

The sniffer does minimal work here: it only grabs each frame and (in live mode) puts it on a queue so the capture thread is never slowed down by analysis.

---

## 2. Extract

**Where:** `sniffer.py` — `_extract_packet_info()` → `PacketInfo`

Each raw packet is turned into a simple **PacketInfo** object with:
- Who is talking: source IP, destination IP  
- How much data: payload size  
- When: timestamp  
- Where (ports): source port, destination port  
- What app (if detectable): e.g. HTTP, TLS, DNS  

This step ignores non-IP or malformed packets so the rest of the pipeline only sees clean, usable data.

---

## 3. Analyze

**Where:** `analyzer.py` — `DetectionEngine.analyze_packet()`

Each **PacketInfo** is checked against four HSE-relevant behaviors:

| Check | What we look for | Why it matters for HSE |
|-------|------------------|-------------------------|
| **Exfiltration** | Internal host sending a lot of data to an external IP | Stolen/encrypted data being sent out |
| **C2 Beaconing** | Same internal→external pair talking at very regular intervals | Malware “phoning home” on a schedule |
| **Port Scan** | One host probing many ports on another (internal) host | Recon before spreading or encrypting |
| **Traffic Spike** | One host suddenly sending much more than its usual rate | Burst of activity (e.g. encryption or exfiltration) |

The engine keeps small, sliding windows of history (per flow or per host) and only raises an alert when a threshold is crossed and cooldowns allow it (to avoid alert storms).

---

## 4. Alert

**Where:** `main.py` (packet callback) + `logger.py` + `ui.py`

When the analyzer returns one or more **SecurityAlert** objects:
- They are **logged** (e.g. to `alerts_log.csv`)  
- Optionally, **PCAP export** is triggered for high-severity alerts (forensics)  
- The **dashboard** is updated so you see recent flows and active alerts in real time  

---

## One-Sentence Summary

**Capture** raw packets → **Extract** them into PacketInfo → **Analyze** for exfiltration, beaconing, port scan, and traffic spike → **Alert** by logging, exporting PCAP, and updating the UI.
