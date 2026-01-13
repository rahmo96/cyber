"""
Threat Detection Engine Module

This module provides static analysis capabilities to detect suspicious patterns
in files, including macro-like signatures and calculates SHA-256 hashes for
forensic purposes.
"""

import hashlib
import re
from pathlib import Path
from typing import List, Dict, Optional


class ThreatAnalyzer:
    """
    Analyzes files for suspicious patterns and calculates cryptographic hashes.
    
    This class implements static analysis to detect potential threats without
    executing any code, making it safe for use in a sandbox environment.
    """
    
    # Suspicious patterns that may indicate malicious macros or scripts
    SUSPICIOUS_PATTERNS = [
        (r'(?i)\bAutoOpen\b', 'AutoOpen Macro'),
        (r'(?i)\bShell\b', 'Shell Execution'),
        (r'(?i)\bExecute\b', 'Execute Command'),
        (r'(?i)\bBase64\b', 'Base64 Encoding'),
        (r'(?i)\bPowerShell\b', 'PowerShell Command'),
        (r'(?i)\bcmd\.exe\b', 'Command Prompt Execution'),
        (r'(?i)\bwscript\.shell\b', 'WScript Shell'),
        (r'(?i)\bCreateObject\s*\(', 'Object Creation'),
        (r'(?i)\bActiveXObject\b', 'ActiveX Object'),
        (r'(?i)\beval\s*\(', 'Eval Function'),
        (r'(?i)\bexec\s*\(', 'Exec Function'),
        (r'(?i)\bdownloadstring\b', 'Download String'),
        (r'(?i)\binvoke-expression\b', 'Invoke Expression'),
        (r'(?i)\binvoke-item\b', 'Invoke Item'),
        (r'(?i)\bstart-process\b', 'Start Process'),
    ]
    
    def __init__(self):
        """Initialize the ThreatAnalyzer with compiled regex patterns."""
        self.compiled_patterns = [
            (re.compile(pattern), description)
            for pattern, description in self.SUSPICIOUS_PATTERNS
        ]
    
    def calculate_sha256(self, file_path: Path) -> str:
        """
        Calculate the SHA-256 hash of a file.
        
        Args:
            file_path: Path to the file to hash
            
        Returns:
            Hexadecimal string representation of the SHA-256 hash
            
        Raises:
            FileNotFoundError: If the file does not exist
            IOError: If the file cannot be read
        """
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
        except Exception as e:
            raise IOError(f"Error reading file {file_path}: {str(e)}")
        
        return sha256_hash.hexdigest()
    
    def scan_file(self, file_path: Path) -> Dict[str, any]:
        """
        Scan a file for suspicious patterns and calculate its hash.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary containing:
                - 'file_path': Path to the scanned file
                - 'sha256': SHA-256 hash of the file
                - 'threats_detected': List of detected threat descriptions
                - 'is_threat': Boolean indicating if any threats were found
                - 'file_size': Size of the file in bytes
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        threats_detected: List[str] = []
        file_size = file_path.stat().st_size
        
        # Calculate hash
        sha256 = self.calculate_sha256(file_path)
        
        # Try to read file content for pattern matching
        # Only read text-based files, skip binary files that might cause issues
        try:
            # Attempt to read as text with multiple encodings
            content = None
            encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read()
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue
            
            # If we couldn't read as text, try reading as bytes and decode with errors='ignore'
            if content is None:
                with open(file_path, 'rb') as f:
                    raw_content = f.read()
                    content = raw_content.decode('utf-8', errors='ignore')
            
            # Scan for suspicious patterns
            for pattern, description in self.compiled_patterns:
                if pattern.search(content):
                    if description not in threats_detected:
                        threats_detected.append(description)
        
        except Exception as e:
            # If we can't read the file, we'll still return the hash
            # but mark it as potentially suspicious due to read errors
            threats_detected.append(f"File read error: {str(e)}")
        
        return {
            'file_path': str(file_path),
            'sha256': sha256,
            'threats_detected': threats_detected,
            'is_threat': len(threats_detected) > 0,
            'file_size': file_size
        }

