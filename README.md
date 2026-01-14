# NetGuard-CLI: HSE-Incident Detection Tool

A Python CLI application for real-time network traffic analysis and detection of HSE ransomware attack patterns. This tool monitors network traffic to identify data exfiltration, C2 beaconing, and port scanning behaviors similar to those observed in the 2021 HSE (Health Service Executive) ransomware attack.

## Overview

NetGuard-CLI is designed to detect three critical attack patterns associated with ransomware operations:

1. **Data Exfiltration**: Identifies large data transfers from internal networks to external IPs
2. **C2 Beaconing**: Detects consistent communication patterns with command-and-control servers
3. **Port Scanning**: Identifies rapid port enumeration attempts within internal networks

## HSE Attack Context

### The 2021 HSE Ransomware Attack

The Health Service Executive (HSE) of Ireland suffered a devastating ransomware attack in May 2021, orchestrated by the Conti ransomware group. This attack disrupted healthcare services across Ireland and resulted in significant data exfiltration.

### Attack Stages Detected by NetGuard-CLI

#### 1. Data Exfiltration Stage
During the HSE attack, attackers exfiltrated approximately 700 GB of sensitive healthcare data before deploying ransomware. NetGuard-CLI detects this pattern by:
- Monitoring cumulative data transfers from internal IPs to external IPs
- Alerting when any external IP receives more than 5MB (configurable) within a 30-second window
- This helps identify potential data exfiltration before the full attack is deployed

#### 2. C2 Beaconing Stage
The attackers used Cobalt Strike C2 (Command and Control) infrastructure to maintain persistent communication. NetGuard-CLI detects this by:
- Identifying consistent communication intervals (e.g., every 5 seconds) between internal IPs and external IPs
- Pattern matching against known beaconing behaviors
- This helps identify compromised systems maintaining C2 communication

#### 3. Port Scanning Stage
Initial reconnaissance involved port scanning to identify vulnerable systems. NetGuard-CLI detects this by:
- Monitoring rapid connection attempts to multiple ports
- Alerting when a single internal IP contacts more than 10 different ports on another internal IP within 10 seconds
- This helps identify lateral movement and reconnaissance activities

## Installation

### Prerequisites

- Python 3.8 or higher
- Administrator/root privileges (for live packet capture)
- Network interface access

### Install Dependencies

```bash
pip install -r requirements.txt
```

**Note**: On Linux, you may need to install additional dependencies for scapy:
```bash
# Ubuntu/Debian
sudo apt-get install python3-dev libpcap-dev

# macOS
brew install libpcap
```

## Usage

### Live Capture Mode

Monitor live network traffic on a specific interface:

```bash
# Default interface
python main.py

# Specific interface
python main.py --interface eth0

# Windows example
python main.py --interface "Ethernet"
```

### Simulation Mode

Test the tool using a pre-captured pcap file:

```bash
python main.py --pcap capture.pcap
```

### Custom Thresholds

Adjust detection thresholds:

```bash
# Custom exfiltration threshold (10 MB)
python main.py --threshold 10.0

# Custom beaconing interval (10 seconds)
python main.py --beacon-interval 10

# Custom port scan threshold (20 ports)
python main.py --port-threshold 20

# Combined example
python main.py --interface eth0 --threshold 10.0 --beacon-interval 7 --port-threshold 15
```

### Command-Line Arguments

```
--interface, -i    Network interface to capture from (default: default interface)
--pcap, -p         Path to .pcap file for simulation mode
--threshold, -t    Exfiltration threshold in MB (default: 5.0)
--beacon-interval, -b  Expected beaconing interval in seconds (default: 5)
--port-threshold   Port scan threshold - number of ports to trigger alert (default: 10)
```

## Dashboard Features

The CLI dashboard provides real-time visualization:

- **Recent Network Flows Table**: Displays the most recent network connections with source/destination IPs, protocols, ports, and payload sizes
- **Security Alerts Panel**: Shows high-priority security alerts in red, with timestamps and detailed descriptions
- **Status Bar**: Displays total packets processed, total alerts detected, and runtime

## Output

### Console Dashboard

The tool displays a live-updating dashboard showing:
- Recent network flows
- Active security alerts
- Real-time statistics

### CSV Logging

All detected anomalies are automatically logged to `alerts_log.csv` with the following columns:
- `timestamp`: ISO format timestamp
- `alert_type`: Type of alert (Data Exfiltration, C2 Beaconing, Port Scan)
- `severity`: Alert severity (HIGH, MEDIUM)
- `description`: Detailed description of the alert
- `source_ip`: Source IP address
- `dest_ip`: Destination IP address
- `details`: Additional alert details (JSON string)

## Architecture

### Module Structure

- **`sniffer.py`**: Packet capture and extraction using scapy
- **`analyzer.py`**: Detection engine with three detection algorithms
- **`logger.py`**: CSV logging functionality
- **`ui.py`**: Rich library-based CLI dashboard
- **`main.py`**: Main entry point and application orchestration

### Detection Algorithms

1. **Exfiltration Detection**: Sliding window tracking of data volumes per external IP
2. **Beaconing Detection**: Statistical analysis of communication intervals
3. **Port Scan Detection**: Time-windowed port access counting

## Security Considerations

- **Administrator Access**: Live packet capture requires elevated privileges
- **Network Monitoring**: This tool monitors network traffic and should only be used on networks you own or have explicit permission to monitor
- **Privacy**: Be aware that packet capture may contain sensitive data
- **Testing**: Always test in simulation mode first using pcap files

## Limitations

- Detection is based on heuristics and may produce false positives
- Encrypted traffic payload sizes are still visible but content is not analyzed
- Detection windows are configurable but may need tuning for specific network environments
- Internal IP detection uses RFC 1918 ranges by default (configurable)

## Example Scenarios

### Detecting Data Exfiltration

```bash
# Monitor for large data transfers
python main.py --interface eth0 --threshold 5.0
```

When an internal IP sends more than 5MB to an external IP within 30 seconds, an alert is triggered.

### Detecting C2 Beaconing

```bash
# Monitor for 5-second beaconing patterns
python main.py --interface eth0 --beacon-interval 5
```

When an internal IP contacts an external IP at consistent 5-second intervals, an alert is triggered.

### Detecting Port Scans

```bash
# Monitor for port scanning
python main.py --interface eth0 --port-threshold 10
```

When an internal IP accesses more than 10 different ports on another internal IP within 10 seconds, an alert is triggered.

## Troubleshooting

### Permission Errors

On Linux/macOS, you may need sudo privileges:
```bash
sudo python main.py --interface eth0
```

### Interface Not Found

List available interfaces:
```bash
# Linux
ip link show

# macOS
ifconfig

# Windows
ipconfig
```

### No Packets Captured

- Verify interface name is correct
- Check that you have permission to capture on the interface
- Ensure network traffic is present on the interface

## Contributing

This tool is designed for cybersecurity professionals and incident responders. Contributions should maintain code quality, include type hints, and follow the modular architecture.

## License

This tool is provided for educational and security research purposes. Use responsibly and only on networks you own or have permission to monitor.

## References

- HSE Ransomware Attack (2021): A case study in healthcare cybersecurity
- Cobalt Strike: C2 framework commonly used in ransomware operations
- Conti Ransomware Group: Threat actor behind the HSE attack

## Disclaimer

This tool is for authorized security testing and incident detection only. Unauthorized network monitoring may violate laws and regulations. Always obtain proper authorization before monitoring network traffic.

