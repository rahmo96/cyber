"""
CLI Dashboard Module for NetGuard-CLI
Provides real-time visualization using the rich library.
"""

from typing import List
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box
from .sniffer import PacketInfo
from .analyzer import SecurityAlert
import time


class Dashboard:
    """Real-time CLI dashboard for network monitoring."""
    
    def __init__(self):
        """Initialize the dashboard."""
        self.console = Console()
        self.start_time = time.time()
    
    def _create_flows_table(self, flows: List[PacketInfo]) -> Table:
        """
        Create a table displaying recent network flows.
        
        Args:
            flows: List of recent PacketInfo objects
            
        Returns:
            Rich Table object
        """
        table = Table(title="Recent Network Flows", box=box.ROUNDED, show_header=True)
        table.add_column("Time", style="cyan", width=10)
        table.add_column("Source IP", style="green", width=16)
        table.add_column("Dest IP", style="yellow", width=16)
        table.add_column("Proto", style="blue", width=6)
        table.add_column("App", style="magenta", width=12)
        table.add_column("Port", style="white", width=6)
        table.add_column("Size", style="white", width=10, justify="right")

        # Show most recent flows (limit to 15 for display)
        recent_flows = flows[-15:] if len(flows) > 15 else flows

        # Colour-code application protocols so they stand out at a glance
        _APP_STYLES = {
            "HTTP": "bold green",
            "TLS": "bold cyan",
            "TLS/HTTPS": "bold cyan",
            "TLS-ALT": "cyan",
            "DNS": "bold yellow",
            "SSH": "bold red",
            "RDP": "bold red",
            "FTP": "bold magenta",
            "FTP-DATA": "magenta",
            "SMTP": "blue",
            "SMTPS": "blue",
        }

        for flow in reversed(recent_flows):
            timestamp_str = time.strftime("%H:%M:%S", time.localtime(flow.timestamp))
            port_str = str(flow.dest_port) if flow.dest_port else "N/A"
            size_str = f"{flow.payload_size} B"
            app = getattr(flow, "app_protocol", "Unknown")
            app_style = _APP_STYLES.get(app, "dim white")

            table.add_row(
                timestamp_str,
                flow.source_ip,
                flow.dest_ip,
                flow.protocol,
                f"[{app_style}]{app}[/{app_style}]",
                port_str,
                size_str,
            )

        if not flows:
            table.add_row("No flows", "", "", "", "", "", "")
        
        return table
    
    def _create_alerts_panel(self, alerts: List[SecurityAlert]) -> Panel:
        """
        Create a panel displaying security alerts.
        
        Args:
            alerts: List of SecurityAlert objects
            
        Returns:
            Rich Panel object
        """
        if not alerts:
            content = Text("No active alerts", style="green")
            return Panel(content, title="Security Alerts", border_style="green")
        
        # Show most recent alerts (limit to 10)
        recent_alerts = alerts[-10:] if len(alerts) > 10 else alerts
        
        alert_text = Text()
        for alert in reversed(recent_alerts):
            # Color code by severity
            if alert.severity == "HIGH":
                style = "bold red"
            elif alert.severity == "MEDIUM":
                style = "bold yellow"
            else:
                style = "white"
            
            timestamp_str = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
            alert_text.append(f"[{timestamp_str}] ", style="dim")
            alert_text.append(f"[{alert.severity}] ", style=style)
            alert_text.append(f"{alert.alert_type}: ", style="bold")
            alert_text.append(f"{alert.description}\n", style="white")
            alert_text.append(f"  {alert.source_ip} -> {alert.dest_ip}\n", style="dim")
            alert_text.append("\n", style="white")
        
        return Panel(alert_text, title="Security Alerts", border_style="red")
    
    def _create_alert_statistics_table(self, alerts: List[SecurityAlert], total_alerts: int) -> Table:
        """
        Create a table displaying alert statistics breakdown.
        
        Args:
            alerts: List of all SecurityAlert objects (for calculating statistics)
            total_alerts: Total number of alerts detected
            
        Returns:
            Rich Table object
        """
        table = Table(title="Alert Statistics", box=box.ROUNDED, show_header=True)
        table.add_column("Category", style="cyan", width=20)
        table.add_column("Count", style="yellow", width=12, justify="right")
        table.add_column("Percentage", style="green", width=12, justify="right")
        
        if total_alerts == 0:
            table.add_row("Total Alerts", "0", "0%")
            table.add_row("No alerts detected", "", "")
            return table
        
        # Calculate statistics by type
        type_counts = {}
        severity_counts = {}
        
        for alert in alerts:
            # Count by type
            alert_type = alert.alert_type
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
            
            # Count by severity
            severity = alert.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate percentages based on stored alerts (not total, for accuracy)
        alerts_for_stats = len(alerts) if alerts else 1
        
        # Add total row
        table.add_row("Total Alerts", str(total_alerts), "")
        
        # Show note if statistics are based on subset
        if len(alerts) < total_alerts:
            table.add_row(f"[dim](Stats from last {len(alerts)})[/dim]", "", "")
        
        table.add_row("", "", "")  # Separator row
        
        # Add breakdown by type
        table.add_row("[bold]By Type:[/bold]", "", "")
        for alert_type in sorted(type_counts.keys()):
            count = type_counts[alert_type]
            percentage = (count / alerts_for_stats) * 100
            table.add_row(f"  {alert_type}", str(count), f"{percentage:.1f}%")
        
        table.add_row("", "", "")  # Separator row
        
        # Add breakdown by severity
        table.add_row("[bold]By Severity:[/bold]", "", "")
        severity_order = ["HIGH", "MEDIUM", "LOW"]
        for severity in severity_order:
            if severity in severity_counts:
                count = severity_counts[severity]
                percentage = (count / alerts_for_stats) * 100
                # Color code severity
                if severity == "HIGH":
                    severity_style = "bold red"
                elif severity == "MEDIUM":
                    severity_style = "bold yellow"
                else:
                    severity_style = "white"
                table.add_row(f"  [{severity_style}]{severity}[/{severity_style}]", str(count), f"{percentage:.1f}%")
        
        return table
    
    def _create_status_bar(self, total_packets: int, total_alerts: int, runtime: float) -> Text:
        """
        Create a status bar with summary information.
        
        Args:
            total_packets: Total packets processed
            total_alerts: Total alerts detected
            runtime: Runtime in seconds
            
        Returns:
            Rich Text object
        """
        runtime_str = time.strftime("%H:%M:%S", time.gmtime(runtime))
        status = Text()
        status.append("Packets: ", style="bold")
        status.append(f"{total_packets:,}", style="cyan")
        status.append(" | Alerts: ", style="bold")
        status.append(f"{total_alerts}", style="red" if total_alerts > 0 else "green")
        status.append(" | Runtime: ", style="bold")
        status.append(runtime_str, style="blue")
        status.append(" | Press Ctrl+C to stop", style="dim")
        
        return status
    
    def create_layout(
        self,
        flows: List[PacketInfo],
        alerts: List[SecurityAlert],
        total_packets: int,
        total_alerts: int
    ) -> Layout:
        """
        Create the complete dashboard layout.
        
        Args:
            flows: List of recent flows
            alerts: List of active alerts (all alerts for statistics)
            total_packets: Total packets processed
            total_alerts: Total alerts detected
            
        Returns:
            Rich Layout object
        """
        layout = Layout()
        
        # Split into main area and status bar
        layout.split_column(
            Layout(name="main", ratio=9),
            Layout(name="status", size=1)
        )
        
        # Split main area into three sections: flows, alerts, and statistics
        layout["main"].split_row(
            Layout(self._create_flows_table(flows), name="flows"),
            Layout(name="right_side")
        )
        
        # Split right side into alerts and statistics
        layout["right_side"].split_column(
            Layout(self._create_alerts_panel(alerts), name="alerts", ratio=3),
            Layout(self._create_alert_statistics_table(alerts, total_alerts), name="statistics", ratio=2)
        )
        
        # Add status bar
        runtime = time.time() - self.start_time
        layout["status"].update(self._create_status_bar(total_packets, total_alerts, runtime))
        
        return layout
    
    def update_dashboard(
        self,
        live: Live,
        flows: List[PacketInfo],
        alerts: List[SecurityAlert],
        total_packets: int,
        total_alerts: int
    ) -> None:
        """
        Update the live dashboard.
        
        Args:
            live: Rich Live object
            flows: List of recent flows
            alerts: List of active alerts
            total_packets: Total packets processed
            total_alerts: Total alerts detected
        """
        layout = self.create_layout(flows, alerts, total_packets, total_alerts)
        live.update(layout)

