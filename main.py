"""
PyGuard-Sandbox: EDR Simulation Tool

Main entry point for the PyGuard-Sandbox application. This module provides
a CLI dashboard using the rich library to display real-time threat detection
status and manages the overall monitoring workflow.
"""

import json
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from monitor import DirectoryMonitor
from analyzer import ThreatAnalyzer
from actions import IncidentResponse


class PyGuardSandbox:
    """
    Main application class that orchestrates monitoring, analysis, and response.
    
    This class manages the complete EDR simulation workflow including directory
    monitoring, threat detection, incident response, and logging.
    """
    
    def __init__(self, sandbox_dir: Path, quarantine_dir: Path, log_file: Path):
        """
        Initialize the PyGuard-Sandbox application.
        
        Args:
            sandbox_dir: Path to the sandbox directory to monitor
            quarantine_dir: Path to the quarantine directory
            log_file: Path to the activity log JSON file
        """
        self.sandbox_dir = Path(sandbox_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.log_file = Path(log_file)
        self.console = Console()
        
        # Initialize components
        self.analyzer = ThreatAnalyzer()
        self.incident_response = IncidentResponse(self.quarantine_dir)
        self.monitor: Optional[DirectoryMonitor] = None
        
        # Statistics tracking
        self.stats = {
            'total_scanned': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'start_time': datetime.now()
        }
        
        # Recent activity log
        self.recent_activity: List[Dict] = []
        self.max_recent_activity = 10
        
        # Ensure directories exist
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.console.print("\n[yellow]Shutting down PyGuard-Sandbox...[/yellow]")
        self.stop()
        sys.exit(0)
    
    def _log_activity(self, activity: Dict) -> None:
        """
        Log activity to the JSON log file.
        
        Args:
            activity: Dictionary containing activity information
        """
        # Load existing log entries
        log_entries = []
        if self.log_file.exists():
            try:
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    log_entries = json.load(f)
            except (json.JSONDecodeError, IOError):
                log_entries = []
        
        # Add new entry
        log_entries.append(activity)
        
        # Write back to file
        try:
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(log_entries, f, indent=2, ensure_ascii=False)
        except IOError as e:
            self.console.print(f"[red]Error writing to log file: {e}[/red]")
    
    def _process_file(self, file_path: Path) -> None:
        """
        Process a file: analyze it and respond if threats are detected.
        
        Args:
            file_path: Path to the file to process
        """
        # Skip if file doesn't exist or is a directory
        if not file_path.exists() or file_path.is_dir():
            return
        
        # Skip if file is in quarantine directory
        if self.quarantine_dir in file_path.parents:
            return
        
        # Skip if already disarmed
        if file_path.suffix == '.disarmed':
            return
        
        try:
            # Analyze file
            self.stats['total_scanned'] += 1
            scan_result = self.analyzer.scan_file(file_path)
            
            # Create activity log entry
            activity = {
                'timestamp': datetime.now().isoformat(),
                'filename': file_path.name,
                'file_path': str(file_path),
                'sha256': scan_result['sha256'],
                'file_size': scan_result['file_size'],
                'threats_detected': scan_result['threats_detected'],
                'is_threat': scan_result['is_threat'],
                'action_taken': 'None'
            }
            
            # If threat detected, quarantine the file
            if scan_result['is_threat']:
                self.stats['threats_detected'] += 1
                try:
                    quarantine_path = self.incident_response.quarantine_file(
                        file_path,
                        scan_result['sha256']
                    )
                    activity['action_taken'] = f'Quarantined to {quarantine_path}'
                    activity['quarantine_path'] = str(quarantine_path)
                    self.stats['files_quarantined'] += 1
                    
                    self.console.print(
                        f"[red]⚠ THREAT DETECTED[/red]: {file_path.name} "
                        f"-> Quarantined"
                    )
                except Exception as e:
                    activity['action_taken'] = f'Quarantine failed: {str(e)}'
                    self.console.print(
                        f"[red]ERROR[/red]: Failed to quarantine {file_path.name}: {e}"
                    )
            else:
                self.console.print(
                    f"[green]✓ Safe[/green]: {file_path.name} "
                    f"(SHA-256: {scan_result['sha256'][:16]}...)"
                )
            
            # Log activity
            self._log_activity(activity)
            
            # Add to recent activity
            self.recent_activity.insert(0, activity)
            if len(self.recent_activity) > self.max_recent_activity:
                self.recent_activity.pop()
        
        except Exception as e:
            self.console.print(
                f"[red]ERROR[/red]: Failed to process {file_path.name}: {e}"
            )
    
    def _create_dashboard(self) -> Layout:
        """
        Create the dashboard layout using rich.
        
        Returns:
            Layout object containing the dashboard
        """
        layout = Layout()
        
        # Create header
        header = Panel(
            "[bold cyan]PyGuard-Sandbox[/bold cyan] - EDR Simulation Tool\n"
            f"Monitoring: [yellow]{self.sandbox_dir}[/yellow]",
            border_style="cyan"
        )
        
        # Create statistics table
        stats_table = Table(title="Statistics", show_header=True, header_style="bold magenta")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        uptime = datetime.now() - self.stats['start_time']
        stats_table.add_row("Uptime", str(uptime).split('.')[0])
        stats_table.add_row("Files Scanned", str(self.stats['total_scanned']))
        stats_table.add_row("Threats Detected", str(self.stats['threats_detected']))
        stats_table.add_row("Files Quarantined", str(self.stats['files_quarantined']))
        
        quarantine_stats = self.incident_response.get_quarantine_stats()
        stats_table.add_row("Quarantine Files", str(quarantine_stats['total_files']))
        stats_table.add_row(
            "Quarantine Size",
            f"{quarantine_stats['total_size'] / 1024:.2f} KB"
        )
        
        # Create recent activity table
        activity_table = Table(title="Recent Activity", show_header=True, header_style="bold yellow")
        activity_table.add_column("Time", style="dim")
        activity_table.add_column("File", style="cyan")
        activity_table.add_column("Status", justify="center")
        activity_table.add_column("Threats", style="red")
        
        if self.recent_activity:
            for activity in self.recent_activity[:5]:  # Show last 5
                timestamp = datetime.fromisoformat(activity['timestamp'])
                time_str = timestamp.strftime("%H:%M:%S")
                filename = activity['filename']
                
                if activity['is_threat']:
                    status = "[red]⚠ THREAT[/red]"
                    threats = ", ".join(activity['threats_detected'][:2])
                    if len(activity['threats_detected']) > 2:
                        threats += "..."
                else:
                    status = "[green]✓ SAFE[/green]"
                    threats = "None"
                
                activity_table.add_row(time_str, filename, status, threats)
        else:
            activity_table.add_row("--", "No activity yet", "--", "--")
        
        # Create status panel
        monitor_status = "[green]●[/green] ACTIVE" if (
            self.monitor and self.monitor.is_running()
        ) else "[red]●[/red] INACTIVE"
        
        status_panel = Panel(
            f"Monitor Status: {monitor_status}\n"
            f"Log File: {self.log_file}\n"
            f"Quarantine: {self.quarantine_dir}",
            title="System Status",
            border_style="blue"
        )
        
        # Arrange layout
        layout.split_column(
            Layout(header, size=3),
            Layout(name="main", ratio=2)
        )
        
        layout["main"].split_row(
            Layout(stats_table, name="stats"),
            Layout(name="right")
        )
        
        layout["right"].split_column(
            Layout(activity_table, ratio=2),
            Layout(status_panel, size=8)
        )
        
        return layout
    
    def start(self) -> None:
        """Start monitoring the sandbox directory."""
        self.console.print("[bold green]Starting PyGuard-Sandbox...[/bold green]")
        self.console.print(f"Monitoring directory: [cyan]{self.sandbox_dir}[/cyan]")
        self.console.print(f"Quarantine directory: [yellow]{self.quarantine_dir}[/yellow]")
        self.console.print(f"Activity log: [blue]{self.log_file}[/blue]\n")
        
        # Initialize monitor
        self.monitor = DirectoryMonitor(self.sandbox_dir, self._process_file)
        self.monitor.start()
        
        # Display dashboard
        try:
            with Live(self._create_dashboard(), refresh_per_second=2, screen=True) as live:
                while True:
                    live.update(self._create_dashboard())
                    time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self) -> None:
        """Stop monitoring and cleanup."""
        if self.monitor:
            self.monitor.stop()
        self.console.print("[yellow]PyGuard-Sandbox stopped.[/yellow]")


def main():
    """Main entry point for the application."""
    # Define paths relative to the script location
    script_dir = Path(__file__).parent
    sandbox_dir = script_dir / "sandbox_env"
    quarantine_dir = script_dir / "quarantine"
    log_file = script_dir / "activity_log.json"
    
    # Create and start the application
    app = PyGuardSandbox(sandbox_dir, quarantine_dir, log_file)
    app.start()


if __name__ == "__main__":
    main()

