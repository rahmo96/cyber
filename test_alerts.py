"""
Manual trigger test for NetGuard-CLI alerts.

Feeds crafted PacketInfo objects directly to the DetectionEngine and other
modules — no real network traffic or PCAP file needed.

Run with:
    python test_alerts.py
"""

import time
import random
from analyzer import DetectionEngine
from sniffer import PacketInfo
from dpi import DeepPacketInspector
from filters import build_filter, IPRangeFilter, ProtocolFilter

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
                ts: float = None, app_protocol: str = "Unknown",
                protocol: str = "TCP") -> PacketInfo:
    return PacketInfo(
        source_ip=src,
        dest_ip=dst,
        protocol=protocol,
        payload_size=size_bytes,
        source_port=src_port,
        dest_port=dst_port,
        timestamp=ts or time.time(),
        app_protocol=app_protocol,
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


# =============================================================================
# TEST 4 -- TRAFFIC SPIKE (Z-score anomaly detection)
# Build a 15-second baseline of ~10 KB/s, then send a 500 KB burst in 1 second.
# That burst is many standard deviations above the mean -> alert fires.
# =============================================================================
print("\n" + "="*60)
print("TEST 4 -- Traffic Spike (Z-score bandwidth anomaly)")
print("="*60)

engine4 = DetectionEngine(
    exfiltration_threshold_mb=999,   # disable exfiltration alerts for this test
    spike_z_threshold=3.0,
    spike_window_seconds=60,
    spike_min_history_seconds=10,
)

spike_start = time.time() + 3000
EXTERNAL_IP_3 = "203.0.113.99"

# Phase 1: build baseline — 15 seconds of noisy ~10 KB/s traffic.
# Real traffic always has some variation; perfectly flat data gives std_dev=0
# which makes Z-score undefined, so we add realistic ±20% jitter.
print("  [Phase 1] Building baseline (15 s of ~8-12 KB/s noisy traffic)...")
random.seed(42)   # deterministic output
for i in range(15):
    # Each second: 1-3 small packets totalling roughly 8-12 KB with jitter
    for _ in range(random.randint(1, 3)):
        size = random.randint(3_000, 7_000)
        pkt = make_packet(INTERNAL_IP, EXTERNAL_IP_3, size_bytes=size,
                          ts=spike_start + i + random.uniform(0, 0.9))
        alerts = engine4.analyze_packet(pkt)
        if alerts:
            print(f"    second {i+1}: unexpected alert -> {alerts[0].description}")

# Phase 2: one large burst — 500 KB in a single second (50x the baseline)
burst_size = 500_000
pkt = make_packet(INTERNAL_IP, EXTERNAL_IP_3, size_bytes=burst_size,
                  ts=spike_start + 16)
alerts = engine4.analyze_packet(pkt)
print(f"  [Phase 2] Sending burst ({burst_size//1024} KB in 1 second)...")
if alerts:
    fired = True
    print_alerts("", alerts)
else:
    print("  [WARN] traffic spike alert did NOT fire")


# =============================================================================
# TEST 5 -- DEEP PACKET INSPECTION (DPI)
# Show that the DPI engine correctly identifies protocols from raw payloads.
# =============================================================================
print("\n" + "="*60)
print("TEST 5 -- Deep Packet Inspection (DPI payload identification)")
print("="*60)

dpi = DeepPacketInspector()

cases = [
    # (description, payload_bytes, src_port, dst_port, transport, expected)
    ("HTTP GET request",   b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", None, 80,  "TCP", "HTTP"),
    ("HTTP response",      b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",          80,   None, "TCP", "HTTP"),
    ("TLS ClientHello",    bytes([0x16, 0x03, 0x01, 0x00, 0x05]),                    None, 443, "TCP", "TLS"),
    ("SSH banner",         b"SSH-2.0-OpenSSH_8.9\r\n",                               None, 22,  "TCP", "SSH"),
    ("DNS query (UDP/53)", b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",    None, 53,  "UDP", "DNS"),
    ("RDP TPKT header",    bytes([0x03, 0x00, 0x00, 0x2f]),                          None, 3389,"TCP", "RDP"),
    ("Port fallback SMTP", b"",                                                       None, 25,  "TCP", "SMTP"),
    ("Unknown payload",    b"\xde\xad\xbe\xef\xca\xfe",                              None, 9999,"TCP", "Unknown"),
]

all_pass = True
for desc, payload, src_port, dst_port, transport, expected in cases:
    result = dpi.identify(payload, src_port, dst_port, transport)
    ok = result == expected
    if not ok:
        all_pass = False
    status = "[OK]  " if ok else "[FAIL]"
    print(f"  {status} {desc:<30} -> {result} (expected {expected})")

if all_pass:
    print("  All DPI tests passed.")


# =============================================================================
# TEST 6 -- TRAFFIC FILTERS
# Show that the filter system accepts/rejects packets correctly.
# =============================================================================
print("\n" + "="*60)
print("TEST 6 -- Traffic Filters (IP range + protocol composition)")
print("="*60)

internal_pkt  = make_packet("192.168.1.50", "8.8.8.8",     app_protocol="DNS",   protocol="UDP")
external_pkt  = make_packet("5.5.5.5",      "8.8.8.8",     app_protocol="DNS",   protocol="UDP")
http_pkt      = make_packet("192.168.1.50", "93.184.216.34",app_protocol="HTTP",  protocol="TCP")
tls_pkt       = make_packet("192.168.1.50", "93.184.216.34",app_protocol="TLS",   protocol="TCP")

filter_cases = [
    # (filter, packet, expected_match, description)
    (IPRangeFilter("192.168.0.0/16"),  internal_pkt,  True,  "IPRange 192.168.0.0/16 vs internal src"),
    (IPRangeFilter("192.168.0.0/16"),  external_pkt,  False, "IPRange 192.168.0.0/16 vs fully external"),
    (ProtocolFilter("DNS"),            internal_pkt,  True,  "ProtocolFilter DNS vs DNS packet"),
    (ProtocolFilter("DNS"),            http_pkt,      False, "ProtocolFilter DNS vs HTTP packet"),
    (ProtocolFilter("HTTP", "TLS"),    http_pkt,      True,  "ProtocolFilter HTTP|TLS vs HTTP packet"),
    (ProtocolFilter("HTTP", "TLS"),    tls_pkt,       True,  "ProtocolFilter HTTP|TLS vs TLS packet"),
    # Composed: internal subnet AND (HTTP or TLS)
    (IPRangeFilter("192.168.0.0/16") & ProtocolFilter("HTTP", "TLS"), http_pkt, True,
     "IPRange AND Protocol vs internal HTTP"),
    (IPRangeFilter("192.168.0.0/16") & ProtocolFilter("HTTP", "TLS"), internal_pkt, False,
     "IPRange AND Protocol vs internal DNS (wrong proto)"),
    (~ProtocolFilter("DNS"),           http_pkt,      True,  "NOT DNS vs HTTP packet"),
    (~ProtocolFilter("DNS"),           internal_pkt,  False, "NOT DNS vs DNS packet"),
]

all_pass = True
for f, pkt, expected, desc in filter_cases:
    result = f.matches(pkt)
    ok = result == expected
    if not ok:
        all_pass = False
    status = "[OK]  " if ok else "[FAIL]"
    print(f"  {status} {desc}")

if all_pass:
    print("  All filter tests passed.")


print("\nDone.\n")
