"""
Directory Monitoring Module

This module provides real-time monitoring of the sandbox directory using
the watchdog library to detect file creation, modification, and deletion events.
"""

from pathlib import Path
from typing import Callable, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


class SandboxMonitor(FileSystemEventHandler):
    """
    Monitors the sandbox directory for file system events.
    
    This class extends FileSystemEventHandler to handle file creation,
    modification, and deletion events in real-time.
    """
    
    def __init__(self, callback: Callable[[Path], None]):
        """
        Initialize the sandbox monitor.
        
        Args:
            callback: Function to call when a file is created or modified.
                     Should accept a Path object as argument.
        """
        super().__init__()
        self.callback = callback
    
    def on_created(self, event: FileSystemEvent) -> None:
        """
        Handle file creation events.
        
        Args:
            event: File system event object
        """
        if not event.is_directory:
            file_path = Path(event.src_path)
            self.callback(file_path)
    
    def on_modified(self, event: FileSystemEvent) -> None:
        """
        Handle file modification events.
        
        Args:
            event: File system event object
        """
        if not event.is_directory:
            file_path = Path(event.src_path)
            # Only process if file exists (not deleted)
            if file_path.exists():
                self.callback(file_path)


class DirectoryMonitor:
    """
    Manages the directory monitoring observer and event handling.
    
    This class wraps the watchdog Observer to provide a clean interface
    for starting and stopping directory monitoring.
    """
    
    def __init__(self, watch_path: Path, callback: Callable[[Path], None]):
        """
        Initialize the directory monitor.
        
        Args:
            watch_path: Path to the directory to monitor
            callback: Function to call when files are detected
        """
        self.watch_path = Path(watch_path)
        self.callback = callback
        self.observer: Optional[Observer] = None
        self.event_handler = SandboxMonitor(callback)
    
    def start(self) -> None:
        """Start monitoring the directory."""
        if not self.watch_path.exists():
            self.watch_path.mkdir(parents=True, exist_ok=True)
        
        self.observer = Observer()
        self.observer.schedule(
            self.event_handler,
            str(self.watch_path),
            recursive=False  # Only monitor top-level directory
        )
        self.observer.start()
    
    def stop(self) -> None:
        """Stop monitoring the directory."""
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
    
    def is_running(self) -> bool:
        """
        Check if the monitor is currently running.
        
        Returns:
            True if monitoring is active, False otherwise
        """
        return self.observer is not None and self.observer.is_alive()

