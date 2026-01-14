"""
Logger Module for NetGuard-CLI
Logs security alerts to CSV file.
"""

import csv
import os
from typing import List
from analyzer import SecurityAlert
from datetime import datetime


class AlertLogger:
    """Logs security alerts to CSV file."""
    
    def __init__(self, log_file: str = "alerts_log.csv"):
        """
        Initialize the alert logger.
        
        Args:
            log_file: Path to CSV log file
        """
        self.log_file = log_file
        self._ensure_header()
    
    def _ensure_header(self) -> None:
        """Ensure CSV file has proper header if it doesn't exist."""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'timestamp',
                    'alert_type',
                    'severity',
                    'description',
                    'source_ip',
                    'dest_ip',
                    'details'
                ])
                writer.writeheader()
    
    def log_alert(self, alert: SecurityAlert) -> None:
        """
        Log a single security alert to CSV.
        
        Args:
            alert: SecurityAlert object to log
        """
        try:
            with open(self.log_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'timestamp',
                    'alert_type',
                    'severity',
                    'description',
                    'source_ip',
                    'dest_ip',
                    'details'
                ])
                writer.writerow(alert.to_dict())
        except Exception as e:
            print(f"Error logging alert: {e}")
    
    def log_alerts(self, alerts: List[SecurityAlert]) -> None:
        """
        Log multiple security alerts to CSV.
        
        Args:
            alerts: List of SecurityAlert objects to log
        """
        for alert in alerts:
            self.log_alert(alert)

