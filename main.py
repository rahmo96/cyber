"""
Main Entry Point for NetGuard-CLI
HSE-Incident Detection Tool
"""

import argparse
import signal
import sys
import time
from typing import Optional
from rich.console import Console
from rich.live import Live
from sniffer import NetworkSniffer
from analyzer import DetectionEngine
from logger import AlertLogger
from ui import Dashboard


class NetGuardCLI:
    """Main application class for NetGuard-CLI."""
    
    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        exfiltration_threshold: float = 1.0,
        beaconing_interval: int = 5,
        port_scan_threshold: int = 5
    ):
        """
        Initialize NetGuard-CLI.
        
        Args:
            interface: Network interface for live capture
            pcap_file: Path to pcap file for simulation mode
            exfiltration_threshold: MB threshold for exfiltration detection
            beaconing_interval: Expected interval in seconds for beaconing
            port_scan_threshold: Number of ports to trigger port scan alert
        """
        self.console = Console()
        self.sniffer = NetworkSniffer(interface=interface, pcap_file=pcap_file)
        self.analyzer = DetectionEngine(
            exfiltration_threshold_mb=exfiltration_threshold,
            beaconing_interval_seconds=beaconing_interval,
            port_scan_threshold=port_scan_threshold
        )
        self.logger = AlertLogger()
        self.dashboard = Dashboard()
        
        self.total_packets = 0
        self.total_alerts = 0
        self.running = True
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.console.print("\n[yellow]Shutting down NetGuard-CLI...[/yellow]")
        self.running = False
        sys.exit(0)
    
    def _packet_callback(self, packet_info) -> None:
        """
        Callback function for each captured packet.
        
        Args:
            packet_info: PacketInfo object
        """
        self.total_packets += 1
        
        # Analyze packet
        alerts = self.analyzer.analyze_packet(packet_info)
        
        # Log alerts
        if alerts:
            self.total_alerts += len(alerts)
            self.logger.log_alerts(alerts)
    
    def run(self) -> None:
        """Run the main monitoring loop."""
        mode_str = "Simulation Mode" if self.sniffer.is_simulation else "Live Capture Mode"
        interface_str = self.sniffer.pcap_file if self.sniffer.is_simulation else (self.sniffer.interface or "default")
        
        self.console.print(f"[bold green]NetGuard-CLI - HSE-Incident Detection Tool[/bold green]")
        self.console.print(f"[cyan]Mode:[/cyan] {mode_str}")
        self.console.print(f"[cyan]Source:[/cyan] {interface_str}")
        self.console.print(f"[cyan]Starting monitoring...[/cyan]\n")
        
        # Create Live display
        with Live(
            self.dashboard.create_layout(
                flows=[],
                alerts=[],
                total_packets=0,
                total_alerts=0
            ),
            refresh_per_second=2,
            screen=True
        ) as live:
            # Start packet capture in a separate thread or use callback
            import threading
            
            def capture_thread():
                try:
                    self.sniffer.start_capture(self._packet_callback)
                except StopIteration:
                    pass
                except Exception as e:
                    self.console.print(f"[red]Error: {e}[/red]")
                    self.running = False
            
            # Start capture thread
            capture_thread_obj = threading.Thread(target=capture_thread, daemon=True)
            capture_thread_obj.start()
            
            # Update dashboard periodically
            while self.running:
                try:
                    flows = self.analyzer.get_recent_flows(limit=20)
                    # Get all alerts for accurate statistics (analyzer stores up to 50)
                    all_alerts = self.analyzer.get_active_alerts(limit=50)
                    # For display, show only recent 10 alerts
                    recent_alerts = all_alerts[-10:] if len(all_alerts) > 10 else all_alerts
                    
                    self.dashboard.update_dashboard(
                        live=live,
                        flows=flows,
                        alerts=all_alerts,  # Pass all alerts for statistics
                        total_packets=self.total_packets,
                        total_alerts=self.total_alerts
                    )
                    
                    time.sleep(0.5)  # Update every 500ms
                    
                    # Check if capture thread is still alive
                    if not capture_thread_obj.is_alive() and self.sniffer.is_simulation:
                        # Simulation mode finished
                        break
                        
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.console.print(f"[red]Dashboard error: {e}[/red]")
                    break
        
        # Final summary
        self.console.print(f"\n[bold]Session Summary:[/bold]")
        self.console.print(f"Total Packets Processed: {self.total_packets:,}")
        self.console.print(f"Total Alerts Detected: {self.total_alerts}")
        self.console.print(f"Alerts logged to: alerts_log.csv")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="NetGuard-CLI: HSE-Incident Detection Tool - Network traffic analyzer for detecting ransomware attack patterns"
    )
    
    parser.add_argument(
        "--interface",
        "-i",
        type=str,
        default=None,
        help="Network interface to capture from (default: default interface)"
    )
    
    parser.add_argument(
        "--pcap",
        "-p",
        type=str,
        default=None,
        help="Path to .pcap file for simulation mode (enables simulation mode)"
    )
    
    parser.add_argument(
        "--threshold",
        "-t",
        type=float,
        default=1.0,
        help="Exfiltration threshold in MB (default: 1.0)"
    )
    
    parser.add_argument(
        "--beacon-interval",
        "-b",
        type=int,
        default=5,
        help="Expected beaconing interval in seconds (default: 5)"
    )
    
    parser.add_argument(
        "--port-threshold",
        type=int,
        default=5,
        help="Port scan threshold - number of ports to trigger alert (default: 5)"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.interface and args.pcap:
        parser.error("Cannot specify both --interface and --pcap. Use --pcap for simulation mode.")
    
    if args.threshold <= 0:
        parser.error("--threshold must be greater than 0")
    
    if args.beacon_interval <= 0:
        parser.error("--beacon-interval must be greater than 0")
    
    if args.port_threshold <= 0:
        parser.error("--port-threshold must be greater than 0")
    
    # Create and run application
    app = NetGuardCLI(
        interface=args.interface,
        pcap_file=args.pcap,
        exfiltration_threshold=args.threshold,
        beaconing_interval=args.beacon_interval,
        port_scan_threshold=args.port_threshold
    )
    
    try:
        app.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

