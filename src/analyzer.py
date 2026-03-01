"""Detection Engine for NetGuard-CLI. Capture -> Extract -> Analyze -> Alert; this is Analyze."""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from .sniffer import PacketInfo
import math
from datetime import datetime

@dataclass
class SecurityAlert:
    """Detected security anomaly."""
    alert_type: str
    severity: str
    description: str
    source_ip: str
    dest_ip: str
    timestamp: float
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'timestamp': datetime.fromtimestamp(self.timestamp).isoformat(),
            'alert_type': self.alert_type, 'severity': self.severity, 'description': self.description,
            'source_ip': self.source_ip, 'dest_ip': self.dest_ip, 'details': str(self.details)
        }

class DetectionEngine:
    """HSE detection: exfiltration, C2 beaconing, port scan, traffic spike."""

    def __init__(
        self,
        exfiltration_threshold_mb: float = 1.0,
        exfiltration_window_seconds: int = 30,
        beaconing_min_interval_seconds: float = 2.0,
        beaconing_cv_threshold: float = 0.15,
        port_scan_threshold: int = 5,
        port_scan_window_seconds: int = 10,
        spike_z_threshold: float = 3.0,
        spike_window_seconds: int = 60,
        spike_min_history_seconds: int = 10,
        internal_ip_ranges: Optional[List[str]] = None
    ):
        self.exfiltration_threshold_bytes = exfiltration_threshold_mb * 1024 * 1024
        self.exfiltration_window = exfiltration_window_seconds
        self.beaconing_min_interval = beaconing_min_interval_seconds
        self.beaconing_cv_threshold = beaconing_cv_threshold
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window_seconds
        self.spike_z_threshold = spike_z_threshold
        self.spike_window = spike_window_seconds
        self.spike_min_history = spike_min_history_seconds
        self.internal_ip_ranges = internal_ip_ranges or ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
        self.exfiltration_tracker: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)
        self.beaconing_tracker: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self.port_scan_tracker: Dict[Tuple[str, str], Dict[int, float]] = defaultdict(lambda: defaultdict(float))
        self._bandwidth_tracker: Dict[str, Dict[int, int]] = defaultdict(dict)
        self._alert_cooldowns: Dict[Tuple[str, str, str], float] = {}
        self.recent_flows: List[PacketInfo] = []
        self.max_recent_flows = 100
        self.active_alerts: List[SecurityAlert] = []
        self.max_alerts = 50

    def _is_internal_ip(self, ip: str) -> bool:
        from ipaddress import ip_address, ip_network
        try:
            ip_obj = ip_address(ip)
            return any(ip_obj in ip_network(r, strict=False) for r in self.internal_ip_ranges)
        except ValueError:
            return False

    def _is_external_ip(self, ip: str) -> bool:
        from ipaddress import ip_address, ip_network
        if self._is_internal_ip(ip):
            return False
        try:
            ip_obj = ip_address(ip)
            if ip in ("255.255.255.255", "0.0.0.0"):
                return False
            if ip_obj in ip_network("224.0.0.0/4", strict=False) or ip_obj in ip_network("169.254.0.0/16", strict=False):
                return False
            return True
        except ValueError:
            return False

    def _cleanup_old_data(self, current_time: float) -> None:
        for key in list(self.exfiltration_tracker.keys()):
            kept = [(ts, sz) for ts, sz in self.exfiltration_tracker[key] if current_time - ts <= self.exfiltration_window]
            self.exfiltration_tracker[key] = kept
            if not kept:
                del self.exfiltration_tracker[key]
        for key in list(self.beaconing_tracker.keys()):
            kept = [ts for ts in self.beaconing_tracker[key] if current_time - ts <= 3600]
            self.beaconing_tracker[key] = kept
            if not kept:
                del self.beaconing_tracker[key]
        for key in list(self.port_scan_tracker.keys()):
            ports = self.port_scan_tracker[key]
            for port in list(ports.keys()):
                if current_time - ports[port] > self.port_scan_window:
                    del ports[port]
            if not ports:
                del self.port_scan_tracker[key]
        cur_b = int(current_time)
        for src in list(self._bandwidth_tracker.keys()):
            b = self._bandwidth_tracker[src]
            for bucket in list(b.keys()):
                if cur_b - bucket > self.spike_window:
                    del b[bucket]
            if not b:
                del self._bandwidth_tracker[src]

    def _is_in_cooldown(self, key: Tuple[str, str, str], current_time: float, cooldown_seconds: float) -> bool:
        last = self._alert_cooldowns.get(key)
        return last is not None and (current_time - last) < cooldown_seconds

    def _set_cooldown(self, key: Tuple[str, str, str], current_time: float) -> None:
        self._alert_cooldowns[key] = current_time

    def _detect_exfiltration(self, packet: PacketInfo) -> Optional[SecurityAlert]:
        source_ip, dest_ip = packet.source_ip, packet.dest_ip
        if not (self._is_internal_ip(source_ip) and self._is_external_ip(dest_ip)):
            return None
        key = (source_ip, dest_ip)
        current_time = packet.timestamp
        self.exfiltration_tracker[key].append((current_time, packet.payload_size))
        total_bytes = sum(sz for ts, sz in self.exfiltration_tracker[key] if current_time - ts <= self.exfiltration_window)
        cooldown_key = (source_ip, dest_ip, "Data Exfiltration")
        if total_bytes < self.exfiltration_threshold_bytes:
            self._alert_cooldowns.pop(cooldown_key, None)
            return None
        if self._is_in_cooldown(cooldown_key, current_time, self.exfiltration_window):
            return None
        self._set_cooldown(cooldown_key, current_time)
        mb = total_bytes / (1024 * 1024)
        return SecurityAlert("Data Exfiltration", "HIGH", f"Large data transfer detected: {mb:.2f} MB sent to external IP",
            source_ip, dest_ip, current_time, {'total_bytes': total_bytes, 'mb_transferred': mb, 'window_seconds': self.exfiltration_window})
    
    def _detect_beaconing(self, packet: PacketInfo) -> Optional[SecurityAlert]:
        source_ip, dest_ip = packet.source_ip, packet.dest_ip
        if not (self._is_internal_ip(source_ip) and self._is_external_ip(dest_ip)):
            return None
        key = (source_ip, dest_ip)
        current_time = packet.timestamp
        last = self.beaconing_tracker[key][-1] if self.beaconing_tracker[key] else None
        if last is None or (current_time - last) >= self.beaconing_min_interval:
            self.beaconing_tracker[key].append(current_time)
        if len(self.beaconing_tracker[key]) < 6:
            return None
        timestamps = sorted(self.beaconing_tracker[key])
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))][-8:]
        if len(intervals) < 4:
            return None
        avg_i = sum(intervals) / len(intervals)
        if avg_i < self.beaconing_min_interval:
            return None
        var = sum((x - avg_i) ** 2 for x in intervals) / len(intervals)
        std, cv = math.sqrt(var), (math.sqrt(var) / avg_i) if avg_i > 0 else 1.0
        if cv > self.beaconing_cv_threshold:
            return None
        cooldown_key = (source_ip, dest_ip, "C2 Beaconing")
        if self._is_in_cooldown(cooldown_key, current_time, avg_i * len(intervals)):
            return None
        self._set_cooldown(cooldown_key, current_time)
        return SecurityAlert("C2 Beaconing", "HIGH", f"Regular beaconing to external IP: ~{avg_i:.1f}s (CV={cv:.2f})",
            source_ip, dest_ip, current_time, {'avg_interval_seconds': round(avg_i, 2), 'std_dev_seconds': round(std, 2), 'coefficient_of_variation': round(cv, 3), 'beacon_count': len(timestamps), 'intervals_analysed': len(intervals)})

    def _detect_port_scan(self, packet: PacketInfo) -> Optional[SecurityAlert]:
        source_ip, dest_ip = packet.source_ip, packet.dest_ip
        if not (self._is_internal_ip(source_ip) and self._is_internal_ip(dest_ip)) or packet.dest_port is None:
            return None
        key = (source_ip, dest_ip)
        current_time = packet.timestamp
        self.port_scan_tracker[key][packet.dest_port] = current_time
        ports_in_window = [p for p, ts in self.port_scan_tracker[key].items() if current_time - ts <= self.port_scan_window]
        if len(ports_in_window) <= self.port_scan_threshold:
            return None
        return SecurityAlert("Port Scan", "MEDIUM", f"Port scan detected: {len(ports_in_window)} ports accessed",
            source_ip, dest_ip, current_time, {'ports_scanned': len(ports_in_window), 'ports': sorted(ports_in_window)[:20], 'window_seconds': self.port_scan_window})

    def _detect_traffic_spike(self, packet: PacketInfo) -> Optional[SecurityAlert]:
        src, current_time = packet.source_ip, packet.timestamp
        cur_b = int(current_time)
        buckets = self._bandwidth_tracker[src]
        buckets[cur_b] = buckets.get(cur_b, 0) + packet.payload_size
        completed = {b: v for b, v in buckets.items() if b < cur_b}
        if len(completed) < self.spike_min_history:
            return None
        history = list(completed.values())
        mean = sum(history) / len(history)
        if mean == 0:
            return None
        std = math.sqrt(sum((x - mean) ** 2 for x in history) / len(history))
        if std == 0:
            return None
        z = (buckets[cur_b] - mean) / std
        if z < self.spike_z_threshold:
            return None
        cooldown_key = (src, "*", "Traffic Spike")
        if self._is_in_cooldown(cooldown_key, current_time, 10.0):
            return None
        self._set_cooldown(cooldown_key, current_time)
        return SecurityAlert("Traffic Spike", "MEDIUM", f"Bandwidth spike from {src}: {buckets[cur_b]/1024:.1f} KB/s (Z={z:.1f}, baseline {mean/1024:.1f} KB/s)",
            src, "*", current_time, {'current_rate_bytes': buckets[cur_b], 'mean_rate_bytes': round(mean, 1), 'std_dev_bytes': round(std, 1), 'z_score': round(z, 2), 'history_seconds': len(completed)})

    def analyze_packet(self, packet: PacketInfo) -> List[SecurityAlert]:
        current_time = packet.timestamp
        self._cleanup_old_data(current_time)
        self.recent_flows.append(packet)
        if len(self.recent_flows) > self.max_recent_flows:
            self.recent_flows.pop(0)
        alerts = []
        for det in [self._detect_exfiltration, self._detect_beaconing, self._detect_port_scan, self._detect_traffic_spike]:
            a = det(packet)
            if a:
                alerts.append(a)
        for alert in alerts:
            self.active_alerts.append(alert)
            if len(self.active_alerts) > self.max_alerts:
                self.active_alerts.pop(0)
        return alerts

    def get_recent_flows(self, limit: int = 20) -> List[PacketInfo]:
        return self.recent_flows[-limit:]

    def get_active_alerts(self, limit: int = 10) -> List[SecurityAlert]:
        return self.active_alerts[-limit:]

