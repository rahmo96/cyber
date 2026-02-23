"""
Main Entry Point for NetGuard-CLI
HSE-Incident Detection Tool

Linux notes:
  - Live packet capture requires root privileges OR the Python binary to have
    the cap_net_raw capability set:
        sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
  - Run under sudo for full functionality:
        sudo python3 main.py --interface eth0
  - List available interfaces with:
        ip link show       (Linux)
        python3 -c "from scapy.all import get_if_list; print(get_if_list())"
"""

import _thread
import argparse
import os
import platform
import signal
import sys
import threading
import time
from typing import List, Optional

from rich.console import Console
from rich.live import Live

from analyzer import DetectionEngine
from filters import TrafficFilter, build_filter
from logger import AlertLogger, PcapExporter
from sniffer import NetworkSniffer, PacketInfo
from ui import Dashboard


# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------

def _is_root() -> bool:
    """Return True if the process has root / administrator privileges."""
    try:
        return os.getuid() == 0           # POSIX (Linux / macOS)
    except AttributeError:
        import ctypes                      # Windows fallback
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def _check_privileges(live_capture: bool) -> None:
    """
    Warn (not block) if live capture is requested without root.
    Prints platform-specific instructions so the user knows how to fix it.
    """
    if not live_capture or _is_root():
        return

    console = Console(stderr=True)
    console.print(
        "\n[bold yellow]WARNING: Live packet capture usually requires elevated privileges.[/bold yellow]"
    )

    if platform.system() == "Linux":
        console.print(
            "  Run with sudo:\n"
            "    [cyan]sudo python3 main.py[/cyan]\n\n"
            "  Or grant the Python binary the net_raw capability (no sudo needed at runtime):\n"
            "    [cyan]sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))[/cyan]\n"
            "  Verify with:\n"
            "    [cyan]getcap $(readlink -f $(which python3))[/cyan]\n"
        )
    elif platform.system() == "Darwin":
        console.print(
            "  Run with sudo:\n"
            "    [cyan]sudo python3 main.py[/cyan]\n"
        )
    else:
        console.print(
            "  Run as Administrator or use simulation mode (--pcap <file>).\n"
        )


# ---------------------------------------------------------------------------
# Main application class
# ---------------------------------------------------------------------------

class NetGuardCLI:
    """Main application class for NetGuard-CLI."""

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        exfiltration_threshold: float = 1.0,
        port_scan_threshold: int = 5,
        bpf_filter: str = "",
        filter_ips: Optional[List[str]] = None,
        filter_protocols: Optional[List[str]] = None,
        export_pcap_on_alert: bool = False,
        pcap_output_dir: str = "forensics",
    ) -> None:
        self.console = Console()

        self.sniffer = NetworkSniffer(
            interface=interface,
            pcap_file=pcap_file,
            bpf_filter=bpf_filter,
        )
        self.analyzer = DetectionEngine(
            exfiltration_threshold_mb=exfiltration_threshold,
            port_scan_threshold=port_scan_threshold,
        )
        self.logger = AlertLogger()
        self.dashboard = Dashboard()
        self.pcap_exporter = PcapExporter(self.sniffer, output_dir=pcap_output_dir)

        self.traffic_filter: TrafficFilter = build_filter(
            ip_ranges=filter_ips,
            protocols=filter_protocols,
        )

        self.export_pcap_on_alert = export_pcap_on_alert

        self.total_packets = 0
        self.total_alerts = 0
        self._counter_lock = threading.Lock()

        # Shutdown flag checked by the main dashboard loop
        self._shutdown = threading.Event()

        # Register signal handlers.
        # IMPORTANT: on Linux, calling sys.exit() directly from a signal handler
        # while daemon threads are running can leave the terminal in a broken state
        # (Rich Live never gets to restore the cursor / screen).  Instead we set
        # a flag and use _thread.interrupt_main() to raise KeyboardInterrupt in
        # the main thread so the 'with Live(...)' context manager can exit cleanly.
        signal.signal(signal.SIGINT,  self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------

    def _signal_handler(self, signum, frame) -> None:
        """
        Graceful shutdown on SIGINT / SIGTERM.

        Sets the shutdown flag and raises KeyboardInterrupt in the main thread
        so the 'with Live(...)' block exits cleanly and the terminal is restored.
        """
        self._shutdown.set()
        _thread.interrupt_main()

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def _packet_callback(self, packet_info: PacketInfo) -> None:
        """Called by the sniffer thread for every captured packet."""
        with self._counter_lock:
            self.total_packets += 1

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
                            # Safe to log here; Rich console is thread-safe
                            self.console.log(f"[cyan]PCAP exported:[/cyan] {path}")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Run the main monitoring loop."""
        mode_str = "Simulation Mode" if self.sniffer.is_simulation else "Live Capture Mode"
        source_str = (
            self.sniffer.pcap_file
            if self.sniffer.is_simulation
            else (self.sniffer.interface or "default interface")
        )

        self.console.print("[bold green]NetGuard-CLI -- HSE-Incident Detection Tool[/bold green]")
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
                target=self._run_capture, daemon=True, name="capture"
            )
            capture_thread.start()

            while not self._shutdown.is_set():
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

                    # Exit automatically when pcap replay finishes
                    if not capture_thread.is_alive() and self.sniffer.is_simulation:
                        break

                except KeyboardInterrupt:
                    break
                except Exception as exc:
                    self.console.print(f"[red]Dashboard error: {exc}[/red]")
                    break

        self._shutdown.set()

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
        except (PermissionError, OSError) as exc:
            # Both PermissionError (Python) and OSError (Linux errno EPERM / EACCES)
            # can be raised when running without root on Linux
            self.console.print(f"\n[bold red]Permission error:[/bold red] {exc}")
            if platform.system() == "Linux":
                self.console.print(
                    "[yellow]Tip:[/yellow] Run with [cyan]sudo python3 main.py[/cyan] "
                    "or grant the capability:\n"
                    "  [cyan]sudo setcap cap_net_raw,cap_net_admin=eip "
                    "$(readlink -f $(which python3))[/cyan]"
                )
            self._shutdown.set()
        except StopIteration:
            pass
        except Exception as exc:
            self.console.print(f"[red]Capture error: {exc}[/red]")
            self._shutdown.set()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetGuard-CLI: HSE-Incident Detection Tool",
    )

    parser.add_argument("--interface", "-i", type=str, default=None,
                        help="Network interface for live capture")
    parser.add_argument("--pcap", "-p", type=str, default=None,
                        help="Path to .pcap file for simulation mode")
    parser.add_argument("--threshold", "-t", type=float, default=1.0,
                        help="Exfiltration alert threshold in MB (default: 1.0)")
    parser.add_argument("--port-threshold", type=int, default=5,
                        help="Unique ports to trigger port scan alert (default: 5)")

    args = parser.parse_args()

    if args.interface and args.pcap:
        parser.error("Cannot use --interface and --pcap together.")
    if args.threshold <= 0:
        parser.error("--threshold must be > 0")
    if args.port_threshold <= 0:
        parser.error("--port-threshold must be > 0")

    _check_privileges(live_capture=args.pcap is None)

    app = NetGuardCLI(
        interface=args.interface,
        pcap_file=args.pcap,
        exfiltration_threshold=args.threshold,
        port_scan_threshold=args.port_threshold,
    )

    try:
        app.run()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        Console(stderr=True).print(f"[red]Fatal error:[/red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
