"""
Detection Engine for NetGuard-CLI
Analyzes network traffic patterns to detect HSE ransomware attack behaviors.
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from .sniffer import PacketInfo
import math
import time
from datetime import datetime


@dataclass
class SecurityAlert:
    """Represents a detected security anomaly."""
    alert_type: str
    severity: str
    description: str
    source_ip: str
    dest_ip: str
    timestamp: float
    details: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert alert to dictionary for logging."""
        return {
            'timestamp': datetime.fromtimestamp(self.timestamp).isoformat(),
            'alert_type': self.alert_type,
            'severity': self.severity,
            'description': self.description,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'details': str(self.details)
        }


class DetectionEngine:
    """
    Detection engine for identifying HSE ransomware attack patterns:
    - Data exfiltration (large data transfers to external IPs)
    - C2 beaconing (consistent interval communication)
    - Port scanning (rapid port enumeration)
    """
    
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
        """
        Initialize the detection engine with configurable thresholds.

        Args:
            exfiltration_threshold_mb: Data threshold in MB for exfiltration alert
            exfiltration_window_seconds: Time window for exfiltration detection
            beaconing_min_interval_seconds: Minimum average gap (seconds) to consider
                as beaconing; contacts more frequent than this are assumed normal traffic
            beaconing_cv_threshold: Coefficient of variation threshold (0–1). Gaps whose
                CV is at or below this value are flagged as suspiciously regular.
                0.15 means ≤15% variation around the mean interval.
            port_scan_threshold: Number of unique ports to trigger port scan alert
            port_scan_window_seconds: Time window for port scan detection
            spike_z_threshold: Z-score above which a 1-second bandwidth bucket is
                flagged as a traffic spike (default 3.0, ~99.7th percentile)
            spike_window_seconds: Rolling baseline window in seconds
            spike_min_history_seconds: Minimum seconds of history before alerting
            internal_ip_ranges: List of IP ranges considered internal (CIDR notation)
        """
        self.exfiltration_threshold_bytes = exfiltration_threshold_mb * 1024 * 1024
        self.exfiltration_window = exfiltration_window_seconds
        self.beaconing_min_interval = beaconing_min_interval_seconds
        self.beaconing_cv_threshold = beaconing_cv_threshold
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window_seconds
        self.spike_z_threshold = spike_z_threshold
        self.spike_window = spike_window_seconds
        self.spike_min_history = spike_min_history_seconds
        
        # Default internal IP ranges (RFC 1918 private addresses)
        if internal_ip_ranges is None:
            self.internal_ip_ranges = [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "127.0.0.0/8"
            ]
        else:
            self.internal_ip_ranges = internal_ip_ranges
        
        # Data structures for tracking
        self.exfiltration_tracker: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)
        self.beaconing_tracker: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self.port_scan_tracker: Dict[Tuple[str, str], Dict[int, float]] = defaultdict(lambda: defaultdict(float))

        # Bandwidth spike tracker: source_ip → {unix_second_bucket: bytes_in_that_second}
        self._bandwidth_tracker: Dict[str, Dict[int, int]] = defaultdict(dict)

        # Cooldown tracker: (source_ip, dest_ip, alert_type) → last alert timestamp
        # Prevents the same alert firing on every packet after a threshold is crossed.
        self._alert_cooldowns: Dict[Tuple[str, str, str], float] = {}
        
        # Recent flows for UI display
        self.recent_flows: List[PacketInfo] = []
        self.max_recent_flows = 100
        
        # Active alerts
        self.active_alerts: List[SecurityAlert] = []
        self.max_alerts = 50
    
    def _is_internal_ip(self, ip: str) -> bool:
        """
        Check if an IP address is internal (private).
        
        Args:
            ip: IP address string
            
        Returns:
            True if IP is internal, False otherwise
        """
        from ipaddress import ip_address, ip_network
        
        try:
            ip_obj = ip_address(ip)
            for ip_range in self.internal_ip_ranges:
                if ip_obj in ip_network(ip_range, strict=False):
                    return True
            return False
        except ValueError:
            return False
    
    def _is_external_ip(self, ip: str) -> bool:
        """
        Check if an IP address is external (public internet).
        Excludes special addresses like broadcast, multicast, and link-local.
        
        Args:
            ip: IP address string
            
        Returns:
            True if IP is external/public, False otherwise
        """
        from ipaddress import ip_address, ip_network
        
        # First check if it's internal
        if self._is_internal_ip(ip):
            return False
        
        try:
            ip_obj = ip_address(ip)
            
            # Exclude special addresses that shouldn't be considered external:
            # - 255.255.255.255 (broadcast)
            # - 0.0.0.0 (unspecified/any)
            if ip == "255.255.255.255" or ip == "0.0.0.0":
                return False
            
            # Exclude multicast addresses (224.0.0.0/4)
            multicast_network = ip_network("224.0.0.0/4", strict=False)
            if ip_obj in multicast_network:
                return False
            
            # Exclude link-local addresses (169.254.0.0/16)
            link_local_network = ip_network("169.254.0.0/16", strict=False)
            if ip_obj in link_local_network:
                return False
            
            # If it's not internal and not special, it's external
            return True
        except ValueError:
            return False
    
    def _cleanup_old_data(self, current_time: float) -> None:
        """Remove old data outside detection windows."""
        # Clean exfiltration tracker
        for key in list(self.exfiltration_tracker.keys()):
            self.exfiltration_tracker[key] = [
                (ts, size) for ts, size in self.exfiltration_tracker[key]
                if current_time - ts <= self.exfiltration_window
            ]
            if not self.exfiltration_tracker[key]:
                del self.exfiltration_tracker[key]
        
        # Clean beaconing tracker
        for key in list(self.beaconing_tracker.keys()):
            self.beaconing_tracker[key] = [
                ts for ts in self.beaconing_tracker[key]
                if current_time - ts <= 3600  # Keep up to 1 hour of history
            ]
            if not self.beaconing_tracker[key]:
                del self.beaconing_tracker[key]
        
        # Clean port scan tracker
        for key in list(self.port_scan_tracker.keys()):
            ports = self.port_scan_tracker[key]
            for port in list(ports.keys()):
                if current_time - ports[port] > self.port_scan_window:
                    del ports[port]
            if not ports:
                del self.port_scan_tracker[key]

        # Clean bandwidth spike tracker
        current_bucket = int(current_time)
        for src in list(self._bandwidth_tracker.keys()):
            for bucket in list(self._bandwidth_tracker[src].keys()):
                if current_bucket - bucket > self.spike_window:
                    del self._bandwidth_tracker[src][bucket]
            if not self._bandwidth_tracker[src]:
                del self._bandwidth_tracker[src]
    
    def _is_in_cooldown(self, key: Tuple[str, str, str], current_time: float, cooldown_seconds: float) -> bool:
        """Return True if the alert key is still within its cooldown window."""
        last = self._alert_cooldowns.get(key)
        return last is not None and (current_time - last) < cooldown_seconds

    def _set_cooldown(self, key: Tuple[str, str, str], current_time: float) -> None:
        """Record the current time as the last-fired timestamp for the given alert key."""
        self._alert_cooldowns[key] = current_time

    def _detect_exfiltration(self, packet: PacketInfo) -> Optional[SecurityAlert]:
        """
        Detect data exfiltration: large data transfers to external IPs.
        
        Args:
            packet: Packet information
            
        Returns:
            SecurityAlert if exfiltration detected, None otherwise
        """
        source_ip = packet.source_ip
        dest_ip = packet.dest_ip
        
        # Only check if internal IP is sending to external IP
        if not (self._is_internal_ip(source_ip) and self._is_external_ip(dest_ip)):
            return None
        
        key = (source_ip, dest_ip)
        current_time = packet.timestamp
        
        # Add packet to tracker
        self.exfiltration_tracker[key].append((current_time, packet.payload_size))
        
        # Calculate total data in window
        total_bytes = sum(
            size for ts, size in self.exfiltration_tracker[key]
            if current_time - ts <= self.exfiltration_window
        )
        
        cooldown_key = (source_ip, dest_ip, "Data Exfiltration")
        if total_bytes >= self.exfiltration_threshold_bytes:
            if self._is_in_cooldown(cooldown_key, current_time, self.exfiltration_window):
                return None
            self._set_cooldown(cooldown_key, current_time)
            mb_transferred = total_bytes / (1024 * 1024)
            return SecurityAlert(
                alert_type="Data Exfiltration",
                severity="HIGH",
                description=f"Large data transfer detected: {mb_transferred:.2f} MB sent to external IP",
                source_ip=source_ip,
                dest_ip=dest_ip,
                timestamp=current_time,
                details={
                    'total_bytes': total_bytes,
                    'mb_transferred': mb_transferred,
                    'window_seconds': self.exfiltration_window
                }
            )
        else:
            # Transfer has slowed down — reset cooldown so the next spike fires a fresh alert
            self._alert_cooldowns.pop(cooldown_key, None)

        return None
    
    def _detect_beaconing(self, packet: PacketInfo) -> Optional[SecurityAlert]:
        """
        Detect C2 beaconing: any suspiciously regular communication interval.

        Instead of checking against a single configured interval, this uses the
        coefficient of variation (CV = std_dev / mean) of the recent inter-packet
        gaps. A very low CV means the traffic is arriving at a machine-precise
        cadence — a hallmark of automated C2 heartbeats rather than human browsing.

        Args:
            packet: Packet information

        Returns:
            SecurityAlert if beaconing detected, None otherwise
        """
        source_ip = packet.source_ip
        dest_ip = packet.dest_ip

        # Only flag internal → external communication
        if not (self._is_internal_ip(source_ip) and self._is_external_ip(dest_ip)):
            return None

        key = (source_ip, dest_ip)
        current_time = packet.timestamp

        # One contact event per beaconing_min_interval window.
        # A single HTTP/TLS session produces dozens of packets within milliseconds;
        # recording all of them would pollute the interval history with near-zero gaps,
        # making the CV huge and masking the true beacon cadence.
        last_contact = self.beaconing_tracker[key][-1] if self.beaconing_tracker[key] else None
        if last_contact is None or (current_time - last_contact) >= self.beaconing_min_interval:
            self.beaconing_tracker[key].append(current_time)

        # Need at least 6 contact points (5 intervals) for a reliable pattern
        if len(self.beaconing_tracker[key]) < 6:
            return None

        timestamps = sorted(self.beaconing_tracker[key])
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

        # Analyse the most recent 8 intervals to stay current
        recent_intervals = intervals[-8:]
        if len(recent_intervals) < 4:
            return None

        avg_interval = sum(recent_intervals) / len(recent_intervals)

        # Skip if the average gap is shorter than the minimum threshold —
        # frequent legitimate traffic (e.g. streaming, DNS) would otherwise trigger alerts
        if avg_interval < self.beaconing_min_interval:
            return None

        variance = sum((x - avg_interval) ** 2 for x in recent_intervals) / len(recent_intervals)
        std_dev = math.sqrt(variance)
        cv = std_dev / avg_interval if avg_interval > 0 else 1.0

        if cv > self.beaconing_cv_threshold:
            return None

        cooldown_key = (source_ip, dest_ip, "C2 Beaconing")
        cooldown_window = avg_interval * len(recent_intervals)
        if self._is_in_cooldown(cooldown_key, current_time, cooldown_window):
            return None
        self._set_cooldown(cooldown_key, current_time)

        return SecurityAlert(
            alert_type="C2 Beaconing",
            severity="HIGH",
            description=(
                f"Regular beaconing pattern detected to external IP: "
                f"~{avg_interval:.1f}s interval (CV={cv:.2f})"
            ),
            source_ip=source_ip,
            dest_ip=dest_ip,
            timestamp=current_time,
            details={
                'avg_interval_seconds': round(avg_interval, 2),
                'std_dev_seconds': round(std_dev, 2),
                'coefficient_of_variation': round(cv, 3),
                'beacon_count': len(timestamps),
                'intervals_analysed': len(recent_intervals),
            }
        )
    
    def _detect_port_scan(self, packet: PacketInfo) -> Optional[SecurityAlert]:
        """
        Detect port scanning: rapid connection attempts to multiple ports.
        
        Args:
            packet: Packet information
            
        Returns:
            SecurityAlert if port scan detected, None otherwise
        """
        source_ip = packet.source_ip
        dest_ip = packet.dest_ip
        
        if not (self._is_internal_ip(source_ip) and self._is_internal_ip(dest_ip)):
            return None
        
        if packet.dest_port is None:
            return None
        
        key = (source_ip, dest_ip)
        current_time = packet.timestamp
        
        # Track port access
        self.port_scan_tracker[key][packet.dest_port] = current_time
        
        # Count unique ports accessed in window
        ports_in_window = [
            port for port, ts in self.port_scan_tracker[key].items()
            if current_time - ts <= self.port_scan_window
        ]
        
        if len(ports_in_window) > self.port_scan_threshold:
            return SecurityAlert(
                alert_type="Port Scan",
                severity="MEDIUM",
                description=f"Port scan detected: {len(ports_in_window)} ports accessed",
                source_ip=source_ip,
                dest_ip=dest_ip,
                timestamp=current_time,
                details={
                    'ports_scanned': len(ports_in_window),
                    'ports': sorted(ports_in_window)[:20],  # Limit to first 20
                    'window_seconds': self.port_scan_window
                }
            )
        
        return None
    
    def _detect_traffic_spike(self, packet: PacketInfo) -> Optional[SecurityAlert]:
        """
        Detect sudden bandwidth spikes using a Z-score on a rolling per-second
        histogram.

        How it works:
          1. Packet bytes are accumulated into 1-second time buckets per source IP.
          2. After enough history is collected (spike_min_history_seconds buckets),
             we compute the mean and standard deviation of all completed buckets
             (all except the current, still-filling bucket).
          3. If the current bucket's byte count deviates more than spike_z_threshold
             standard deviations above the mean, a Traffic Spike alert fires.
          4. A per-source 10-second cooldown prevents alert storms.

        Args:
            packet: Packet information

        Returns:
            SecurityAlert if a spike is detected, None otherwise
        """
        src = packet.source_ip
        current_time = packet.timestamp
        current_bucket = int(current_time)

        buckets = self._bandwidth_tracker[src]
        buckets[current_bucket] = buckets.get(current_bucket, 0) + packet.payload_size

        # Need enough completed history buckets before we start comparing
        completed_buckets = {b: v for b, v in buckets.items() if b < current_bucket}
        if len(completed_buckets) < self.spike_min_history:
            return None

        history = list(completed_buckets.values())
        current_rate = buckets[current_bucket]

        mean = sum(history) / len(history)
        if mean == 0:
            return None

        variance = sum((x - mean) ** 2 for x in history) / len(history)
        std_dev = math.sqrt(variance)
        if std_dev == 0:
            return None

        z_score = (current_rate - mean) / std_dev
        if z_score < self.spike_z_threshold:
            return None

        cooldown_key = (src, "*", "Traffic Spike")
        if self._is_in_cooldown(cooldown_key, current_time, 10.0):
            return None
        self._set_cooldown(cooldown_key, current_time)

        return SecurityAlert(
            alert_type="Traffic Spike",
            severity="MEDIUM",
            description=(
                f"Bandwidth spike from {src}: "
                f"{current_rate / 1024:.1f} KB/s (Z={z_score:.1f}, "
                f"baseline avg {mean / 1024:.1f} KB/s)"
            ),
            source_ip=src,
            dest_ip="*",
            timestamp=current_time,
            details={
                'current_rate_bytes': current_rate,
                'mean_rate_bytes': round(mean, 1),
                'std_dev_bytes': round(std_dev, 1),
                'z_score': round(z_score, 2),
                'history_seconds': len(completed_buckets),
            },
        )

    def analyze_packet(self, packet: PacketInfo) -> List[SecurityAlert]:
        """
        Analyze a single packet and return any detected alerts.
        
        Args:
            packet: Packet information to analyze
            
        Returns:
            List of SecurityAlert objects
        """
        alerts = []
        current_time = packet.timestamp
        
        # Cleanup old data
        self._cleanup_old_data(current_time)
        
        # Add to recent flows
        self.recent_flows.append(packet)
        if len(self.recent_flows) > self.max_recent_flows:
            self.recent_flows.pop(0)
        
        # Run detection algorithms
        exfiltration_alert = self._detect_exfiltration(packet)
        if exfiltration_alert:
            alerts.append(exfiltration_alert)
        
        beaconing_alert = self._detect_beaconing(packet)
        if beaconing_alert:
            alerts.append(beaconing_alert)
        
        port_scan_alert = self._detect_port_scan(packet)
        if port_scan_alert:
            alerts.append(port_scan_alert)

        spike_alert = self._detect_traffic_spike(packet)
        if spike_alert:
            alerts.append(spike_alert)
        
        # Add alerts to active alerts list
        for alert in alerts:
            self.active_alerts.append(alert)
            if len(self.active_alerts) > self.max_alerts:
                self.active_alerts.pop(0)
        
        return alerts
    
    def get_recent_flows(self, limit: int = 20) -> List[PacketInfo]:
        """Get recent network flows."""
        return self.recent_flows[-limit:]
    
    def get_active_alerts(self, limit: int = 10) -> List[SecurityAlert]:
        """Get active security alerts."""
        return self.active_alerts[-limit:]

