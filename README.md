# PyGuard-Sandbox

A Python-based CLI tool that simulates an EDR (Endpoint Detection and Response) agent for cybersecurity course projects. This tool monitors a sandbox directory in real-time, detects suspicious patterns in files, and safely quarantines potential threats.

## Features

- **Real-time Directory Monitoring**: Uses the `watchdog` library to monitor the `sandbox_env` folder for file changes
- **Threat Detection Engine**: Static analysis to detect suspicious macro-like signatures (AutoOpen, Shell, Execute, Base64, PowerShell, etc.)
- **SHA-256 Hashing**: Calculates cryptographic hashes for forensic tracking
- **Incident Response**: Automatically quarantines detected threats and renames them with `.disarmed` extension
- **Professional Logging**: JSON-based activity log with timestamps, file hashes, detected threats, and actions taken
- **Beautiful CLI Dashboard**: Rich console interface showing real-time statistics and threat status

## Safety Features

- **Self-contained**: All operations are limited to the project folder
- **No System Modifications**: Never touches Windows Registry or global Office settings
- **Safe Quarantine**: Files are moved to a dedicated quarantine folder and rendered non-executable

## Installation

1. Clone or download this repository
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Start the monitoring tool:

```bash
python main.py
```

2. The tool will create a `sandbox_env` directory if it doesn't exist
3. Place files in the `sandbox_env` directory to test the detection engine
4. Detected threats will be automatically moved to the `quarantine` folder with `.disarmed` extension
5. View the activity log in `activity_log.json`

## Project Structure

```
cyber/
├── main.py              # Main entry point with CLI dashboard
├── monitor.py           # Directory monitoring with watchdog
├── analyzer.py          # Threat detection and hash calculation
├── actions.py           # Quarantine and incident response
├── requirements.txt    # Python dependencies
├── activity_log.json   # Activity log (generated at runtime)
├── sandbox_env/        # Monitored directory (created at runtime)
└── quarantine/         # Quarantine directory (created at runtime)
```

## Detected Threat Patterns

The tool scans for the following suspicious patterns:

- AutoOpen Macro
- Shell Execution
- Execute Command
- Base64 Encoding
- PowerShell Commands
- Command Prompt Execution
- WScript Shell
- Object Creation
- ActiveX Objects
- Eval/Exec Functions
- Download String
- Invoke Expression/Item
- Start Process

## Activity Log Format

The `activity_log.json` file contains entries with the following structure:

```json
{
  "timestamp": "2024-01-15T10:30:45.123456",
  "filename": "suspicious_file.doc",
  "file_path": "C:\\path\\to\\file",
  "sha256": "abc123...",
  "file_size": 1024,
  "threats_detected": ["AutoOpen Macro", "Shell Execution"],
  "is_threat": true,
  "action_taken": "Quarantined to quarantine/suspicious_file.doc.disarmed",
  "quarantine_path": "quarantine/suspicious_file.doc.disarmed"
}
```

## Requirements

- Python 3.7+
- watchdog >= 3.0.0
- rich >= 13.7.0

## License

This project is created for educational purposes as part of a cybersecurity course.

