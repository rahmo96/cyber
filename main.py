"""
Main Entry Point for NetGuard-CLI
HSE-Incident Detection Tool
"""

import argparse
import signal
import sys
import time
import threading
from typing import List, Optional

from rich.console import Console
from rich.live import Live

from sniffer import NetworkSniffer, PacketInfo
from analyzer import DetectionEngine
from logger import AlertLogger, PcapExporter
from ui import Dashboard
from filters import TrafficFilter, build_filter


class NetGuardCLI:
    """Main application class for NetGuard-CLI."""

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        exfiltration_threshold: float = 1.0,
        beaconing_interval: int = 5,
        port_scan_threshold: int = 5,
        bpf_filter: str = "",
        filter_ips: Optional[List[str]] = None,
        filter_protocols: Optional[List[str]] = None,
        export_pcap_on_alert: bool = False,
        pcap_output_dir: str = "forensics",
    ) -> None:
        """
        Args:
            interface:            Network interface for live capture.
            pcap_file:            Path to .pcap file for simulation mode.
            exfiltration_threshold: MB threshold for data exfiltration alert.
            beaconing_interval:   Reference interval (seconds) for legacy CLI compat.
            port_scan_threshold:  Unique port count to trigger port scan alert.
            bpf_filter:           BPF capture filter string (live capture only).
            filter_ips:           CIDR ranges to limit displayed/analysed traffic.
            filter_protocols:     Protocol names to limit displayed/analysed traffic.
            export_pcap_on_alert: Automatically dump the rolling pcap buffer to
                                  disk whenever a HIGH-severity alert fires.
            pcap_output_dir:      Directory for auto-exported pcap files.
        """
        self.console = Console()

        self.sniffer = NetworkSniffer(
            interface=interface,
            pcap_file=pcap_file,
            bpf_filter=bpf_filter,
        )
        self.analyzer = DetectionEngine(
            exfiltration_threshold_mb=exfiltration_threshold,
            beaconing_interval_seconds=beaconing_interval,
            port_scan_threshold=port_scan_threshold,
        )
        self.logger = AlertLogger()
        self.dashboard = Dashboard()
        self.pcap_exporter = PcapExporter(self.sniffer, output_dir=pcap_output_dir)

        # Traffic filter (applied before analysis so irrelevant packets are skipped)
        self.traffic_filter: TrafficFilter = build_filter(
            ip_ranges=filter_ips,
            protocols=filter_protocols,
        )

        self.export_pcap_on_alert = export_pcap_on_alert

        self.total_packets = 0
        self.total_alerts = 0
        self._counter_lock = threading.Lock()
        self.running = True

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals gracefully."""
        self.console.print("\n[yellow]Shutting down NetGuard-CLI...[/yellow]")
        self.running = False
        sys.exit(0)

    def _packet_callback(self, packet_info: PacketInfo) -> None:
        """
        Called by the sniffer for every captured packet.

        Applies the traffic filter, runs detection, logs alerts, and
        optionally exports the pcap buffer on HIGH-severity findings.
        """
        with self._counter_lock:
            self.total_packets += 1

        # Skip packets that don't match the user-defined filter
        if not self.traffic_filter.matches(packet_info):
            return

        alerts = self.analyzer.analyze_packet(packet_info)

        if alerts:
            self.logger.log_alerts(alerts)
            with self._counter_lock:
                self.total_alerts += len(alerts)

            if self.export_pcap_on_alert:
                for alert in alerts:
                    if alert.severity == "HIGH":
                        path = self.pcap_exporter.export_on_alert(alert)
                        if path:
                            self.console.log(
                                f"[cyan]PCAP exported:[/cyan] {path}"
                            )

    def run(self) -> None:
        """Run the main monitoring loop."""
        mode_str = "Simulation Mode" if self.sniffer.is_simulation else "Live Capture Mode"
        source_str = (
            self.sniffer.pcap_file
            if self.sniffer.is_simulation
            else (self.sniffer.interface or "default interface")
        )

        self.console.print("[bold green]NetGuard-CLI — HSE-Incident Detection Tool[/bold green]")
        self.console.print(f"[cyan]Mode:[/cyan]   {mode_str}")
        self.console.print(f"[cyan]Source:[/cyan] {source_str}")
        if self.sniffer.bpf_filter:
            self.console.print(f"[cyan]BPF:[/cyan]    {self.sniffer.bpf_filter}")
        self.console.print("[cyan]Starting monitoring...[/cyan]\n")

        with Live(
            self.dashboard.create_layout(
                flows=[], alerts=[], total_packets=0, total_alerts=0
            ),
            refresh_per_second=2,
            screen=True,
        ) as live:
            capture_thread = threading.Thread(
                target=self._run_capture, daemon=True
            )
            capture_thread.start()

            while self.running:
                try:
                    flows = self.analyzer.get_recent_flows(limit=20)
                    all_alerts = self.analyzer.get_active_alerts(limit=50)

                    with self._counter_lock:
                        packets = self.total_packets
                        alert_count = self.total_alerts

                    self.dashboard.update_dashboard(
                        live=live,
                        flows=flows,
                        alerts=all_alerts,
                        total_packets=packets,
                        total_alerts=alert_count,
                    )
                    time.sleep(0.5)

                    if not capture_thread.is_alive() and self.sniffer.is_simulation:
                        break

                except KeyboardInterrupt:
                    break
                except Exception as exc:
                    self.console.print(f"[red]Dashboard error: {exc}[/red]")
                    break

        with self._counter_lock:
            packets = self.total_packets
            alert_count = self.total_alerts

        self.console.print("\n[bold]Session Summary:[/bold]")
        self.console.print(f"Total Packets Processed: {packets:,}")
        self.console.print(f"Total Alerts Detected:   {alert_count}")
        self.console.print(f"Alerts logged to:        alerts_log.csv")
        if self.export_pcap_on_alert:
            self.console.print(f"PCAP exports saved to:   {self.pcap_exporter._output_dir}/")

    def _run_capture(self) -> None:
        """Entry point for the background capture thread."""
        try:
            self.sniffer.start_capture(self._packet_callback)
        except PermissionError as exc:
            self.console.print(f"[bold red]Permission error:[/bold red] {exc}")
            self.running = False
        except StopIteration:
            pass
        except Exception as exc:
            self.console.print(f"[red]Capture error: {exc}[/red]")
            self.running = False


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "NetGuard-CLI: HSE-Incident Detection Tool — "
            "network traffic analyser for detecting ransomware attack patterns"
        )
    )

    # Capture source
    parser.add_argument(
        "--interface", "-i",
        type=str, default=None,
        help="Network interface for live capture (default: system default)",
    )
    parser.add_argument(
        "--pcap", "-p",
        type=str, default=None,
        help="Path to .pcap file for simulation / replay mode",
    )

    # Detection thresholds
    parser.add_argument(
        "--threshold", "-t",
        type=float, default=1.0,
        help="Exfiltration threshold in MB (default: 1.0)",
    )
    parser.add_argument(
        "--beacon-interval", "-b",
        type=int, default=5,
        help="Reference beaconing interval in seconds (default: 5)",
    )
    parser.add_argument(
        "--port-threshold",
        type=int, default=5,
        help="Port scan threshold — unique ports to trigger alert (default: 5)",
    )

    # Capture filtering
    parser.add_argument(
        "--bpf",
        type=str, default="",
        help='BPF filter for live capture, e.g. "tcp port 443"',
    )
    parser.add_argument(
        "--filter-ip",
        type=str, action="append", default=None, dest="filter_ips",
        metavar="CIDR",
        help=(
            "Only analyse traffic involving this CIDR range "
            "(can be repeated for multiple ranges)"
        ),
    )
    parser.add_argument(
        "--filter-protocol",
        type=str, action="append", default=None, dest="filter_protocols",
        metavar="PROTO",
        help=(
            "Only analyse traffic matching this protocol name, e.g. HTTP, DNS, TLS "
            "(can be repeated)"
        ),
    )

    # PCAP export
    parser.add_argument(
        "--export-pcap",
        action="store_true", default=False,
        help=(
            "Automatically export the rolling packet buffer to a .pcap file "
            "whenever a HIGH-severity alert fires"
        ),
    )
    parser.add_argument(
        "--pcap-output-dir",
        type=str, default="forensics",
        help="Directory for auto-exported .pcap files (default: forensics/)",
    )

    args = parser.parse_args()

    # Argument validation
    if args.interface and args.pcap:
        parser.error("Cannot use --interface and --pcap together.")
    if args.threshold <= 0:
        parser.error("--threshold must be > 0")
    if args.beacon_interval <= 0:
        parser.error("--beacon-interval must be > 0")
    if args.port_threshold <= 0:
        parser.error("--port-threshold must be > 0")

    app = NetGuardCLI(
        interface=args.interface,
        pcap_file=args.pcap,
        exfiltration_threshold=args.threshold,
        beaconing_interval=args.beacon_interval,
        port_scan_threshold=args.port_threshold,
        bpf_filter=args.bpf,
        filter_ips=args.filter_ips,
        filter_protocols=args.filter_protocols,
        export_pcap_on_alert=args.export_pcap,
        pcap_output_dir=args.pcap_output_dir,
    )

    try:
        app.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
