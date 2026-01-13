"""
Incident Response Module

This module handles the quarantine and disarming of detected threats,
ensuring files are safely isolated without affecting the global system.
"""

import shutil
from pathlib import Path
from typing import Optional
from datetime import datetime


class IncidentResponse:
    """
    Handles incident response actions including quarantine and file disarming.
    
    This class ensures that detected threats are safely isolated and rendered
    non-executable by renaming their extensions.
    """
    
    def __init__(self, quarantine_dir: Path):
        """
        Initialize the IncidentResponse handler.
        
        Args:
            quarantine_dir: Path to the quarantine directory where threats are stored
        """
        self.quarantine_dir = Path(quarantine_dir)
        self._ensure_quarantine_dir()
    
    def _ensure_quarantine_dir(self) -> None:
        """Ensure the quarantine directory exists, create if it doesn't."""
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
    
    def quarantine_file(self, file_path: Path, sha256: str) -> Optional[Path]:
        """
        Move a file to quarantine and rename it with .disarmed extension.
        
        Args:
            file_path: Path to the file to quarantine
            sha256: SHA-256 hash of the file for tracking
            
        Returns:
            Path to the quarantined file, or None if operation failed
            
        Raises:
            FileNotFoundError: If the source file does not exist
            IOError: If the quarantine operation fails
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Cannot quarantine non-existent file: {file_path}")
        
        try:
            # Get original filename and extension
            original_name = file_path.name
            stem = file_path.stem
            extension = file_path.suffix
            
            # Create new filename with .disarmed extension
            # Format: original_name.disarmed
            disarmed_name = f"{original_name}.disarmed"
            
            # Create quarantine path
            quarantine_path = self.quarantine_dir / disarmed_name
            
            # If file with same name exists, append timestamp
            if quarantine_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                disarmed_name = f"{stem}_{timestamp}{extension}.disarmed"
                quarantine_path = self.quarantine_dir / disarmed_name
            
            # Move file to quarantine
            shutil.move(str(file_path), str(quarantine_path))
            
            return quarantine_path
        
        except Exception as e:
            raise IOError(f"Failed to quarantine file {file_path}: {str(e)}")
    
    def get_quarantine_stats(self) -> dict:
        """
        Get statistics about quarantined files.
        
        Returns:
            Dictionary containing:
                - 'total_files': Number of files in quarantine
                - 'total_size': Total size of quarantined files in bytes
        """
        total_files = 0
        total_size = 0
        
        if self.quarantine_dir.exists():
            for file_path in self.quarantine_dir.iterdir():
                if file_path.is_file():
                    total_files += 1
                    total_size += file_path.stat().st_size
        
        return {
            'total_files': total_files,
            'total_size': total_size
        }

