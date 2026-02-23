"""
Logger Module for NetGuard-CLI

Handles two kinds of output:
  1. AlertLogger   — appends security alerts to a CSV file (thread-safe).
  2. PcapExporter  — exports the sniffer's rolling packet buffer to a .pcap
                     file whenever a suspicious alert is generated, enabling
                     post-incident forensic analysis in Wireshark.
"""

import csv
import os
import threading
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from .analyzer import SecurityAlert

if TYPE_CHECKING:
    # Avoid a circular import at runtime; only used for type hints
    from .sniffer import NetworkSniffer


class AlertLogger:
    """
    Appends security alerts to a CSV file.

    Thread-safe: a reentrant lock serialises all writes so that alerts from
    the capture thread and the dashboard thread cannot interleave.
    """

    _FIELDNAMES = [
        "timestamp",
        "alert_type",
        "severity",
        "description",
        "source_ip",
        "dest_ip",
        "details",
    ]

    def __init__(self, log_file: str = "alerts_log.csv") -> None:
        """
        Args:
            log_file: Path to the CSV output file.
        """
        self.log_file = log_file
        self._lock = threading.Lock()
        self._ensure_header()

    def log_alert(self, alert: SecurityAlert) -> None:
        """Append a single alert to the CSV file."""
        try:
            with self._lock:
                with open(self.log_file, "a", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=self._FIELDNAMES)
                    writer.writerow(alert.to_dict())
        except Exception as exc:
            # Never crash the main thread because of a logging failure
            print(f"[logger] Error writing alert: {exc}")

    def log_alerts(self, alerts: List[SecurityAlert]) -> None:
        """Append multiple alerts in a single lock acquisition."""
        if not alerts:
            return
        try:
            with self._lock:
                with open(self.log_file, "a", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=self._FIELDNAMES)
                    writer.writerows(a.to_dict() for a in alerts)
        except Exception as exc:
            print(f"[logger] Error writing alerts: {exc}")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ensure_header(self) -> None:
        """Write the CSV header row if the file does not yet exist."""
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", newline="", encoding="utf-8") as fh:
                csv.DictWriter(fh, fieldnames=self._FIELDNAMES).writeheader()


# ---------------------------------------------------------------------------

class PcapExporter:
    """
    Exports the sniffer's rolling packet buffer to a timestamped .pcap file.

    Usage:
        exporter = PcapExporter(sniffer, output_dir="forensics")
        exporter.export(reason="C2 Beaconing detected")

    The resulting file can be opened directly in Wireshark for forensic
    analysis of the traffic leading up to an alert.
    """

    def __init__(
        self,
        sniffer: "NetworkSniffer",
        output_dir: str = "forensics",
    ) -> None:
        """
        Args:
            sniffer:    The NetworkSniffer instance whose buffer to export.
            output_dir: Directory where .pcap files will be saved.
        """
        self._sniffer = sniffer
        self._output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def export(self, reason: str = "") -> Optional[str]:
        """
        Write the current rolling packet buffer to a .pcap file.

        Args:
            reason: Short description included in the filename, e.g.
                    "C2_Beaconing" or "Data_Exfiltration".

        Returns:
            Path to the written file, or None if the buffer was empty.
        """
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_reason = reason.replace(" ", "_").replace("/", "-")[:40]
        filename = os.path.join(
            self._output_dir,
            f"capture_{ts}_{safe_reason}.pcap" if safe_reason else f"capture_{ts}.pcap",
        )

        count = self._sniffer.export_pcap(filename)
        if count == 0:
            return None

        return filename

    def export_on_alert(self, alert: SecurityAlert) -> Optional[str]:
        """
        Convenience wrapper: export the buffer and name the file after the
        alert type, then return the path.

        Designed to be called inside the packet callback whenever a HIGH-
        severity alert fires.
        """
        return self.export(reason=alert.alert_type)
