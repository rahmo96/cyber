"""
Manual trigger test for NetGuard-CLI alerts.

Feeds crafted PacketInfo objects directly to the DetectionEngine — no real
network traffic or PCAP file needed.

Run with:
    python test_alerts.py
"""

import time
from analyzer import DetectionEngine
from sniffer import PacketInfo

INTERNAL_IP = "192.168.1.100"   # simulated local machine
EXTERNAL_IP = "203.0.113.42"    # simulated C2 / attacker server (TEST-NET-3, RFC 5737)

engine = DetectionEngine(
    exfiltration_threshold_mb=1.0,
    port_scan_threshold=5,
    beaconing_min_interval_seconds=2.0,
    beaconing_cv_threshold=0.15,
)

def make_packet(src: str, dst: str, size_bytes: int = 512,
                src_port: int = 54321, dst_port: int = 443,
                ts: float = None) -> PacketInfo:
    return PacketInfo(
        source_ip=src,
        dest_ip=dst,
        protocol="TCP",
        payload_size=size_bytes,
        source_port=src_port,
        dest_port=dst_port,
        timestamp=ts or time.time(),
    )


def print_alerts(label: str, alerts: list) -> None:
    if alerts:
        for a in alerts:
            print(f"  [ALERT] [{a.severity}] {a.alert_type}: {a.description}")
            print(f"          {a.source_ip} -> {a.dest_ip}  |  details: {a.details}")
    else:
        print("  [OK]  no alert")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1 — DATA EXFILTRATION
# Send 1.2 MB from the internal machine to an external IP in one window.
# Threshold is 1.0 MB, so this should fire exactly once.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("TEST 1 — Data Exfiltration (1.2 MB in 30 s window)")
print("="*60)

base_time = time.time()
chunk = 100_000   # 100 KB per packet → 12 packets = 1.2 MB
fired = False
for i in range(12):
    pkt = make_packet(INTERNAL_IP, EXTERNAL_IP, size_bytes=chunk,
                      ts=base_time + i)
    alerts = engine.analyze_packet(pkt)
    label = f"  packet {i+1:02d} (+{chunk//1024}KB, total ~{(i+1)*chunk//1024}KB)"
    if alerts:
        fired = True
        print(f"{label}")
        print_alerts("", alerts)
    else:
        print(f"{label}  -> no alert yet")

if not fired:
    print("  [WARN] exfiltration alert did NOT fire -- check your threshold")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2 — C2 BEACONING
# Send 8 packets from the internal machine to the same external IP, each
# exactly 10 seconds apart. CV will be ~0 → should fire.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("TEST 2 — C2 Beaconing (10-second fixed interval, 8 beacons)")
print("="*60)

engine2 = DetectionEngine(
    exfiltration_threshold_mb=1.0,
    port_scan_threshold=5,
    beaconing_min_interval_seconds=2.0,
    beaconing_cv_threshold=0.15,
)

beacon_start = time.time() + 1000   # offset to avoid overlap with test 1
EXTERNAL_IP_2 = "198.51.100.7"      # different external IP

fired = False
for i in range(8):
    pkt = make_packet(INTERNAL_IP, EXTERNAL_IP_2, size_bytes=128,
                      ts=beacon_start + i * 10.0)   # exactly 10 s apart
    alerts = engine2.analyze_packet(pkt)
    label = f"  beacon {i+1}  (t={beacon_start + i*10.0 - beacon_start:.0f}s)"
    if alerts:
        fired = True
        print(f"{label}")
        print_alerts("", alerts)
    else:
        print(f"{label}  -> no alert yet")

if not fired:
    print("  [WARN] beaconing alert did NOT fire -- check your CV threshold or min interval")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3 — PORT SCAN
# One internal machine hits 8 different ports on another host within 10 s.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("TEST 3 — Port Scan (8 ports in 10 s window)")
print("="*60)

engine3 = DetectionEngine(
    exfiltration_threshold_mb=1.0,
    port_scan_threshold=5,
)

TARGET_IP = "192.168.1.200"
scan_start = time.time() + 2000
ports = [22, 80, 443, 3389, 8080, 8443, 21, 25]

fired = False
for i, port in enumerate(ports):
    pkt = make_packet(INTERNAL_IP, TARGET_IP, size_bytes=40,
                      dst_port=port, ts=scan_start + i * 0.5)
    alerts = engine3.analyze_packet(pkt)
    label = f"  hit port {port:<5}"
    if alerts:
        fired = True
        print(f"{label}")
        print_alerts("", alerts)
    else:
        print(f"{label}  -> no alert yet")

if not fired:
    print("  [WARN] port scan alert did NOT fire -- check your threshold")

print("\nDone.\n")
