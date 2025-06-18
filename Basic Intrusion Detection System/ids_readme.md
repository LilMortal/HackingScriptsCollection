# Basic Intrusion Detection System (IDS)

A lightweight, Python-based intrusion detection system that monitors network traffic, system logs, and system resources for suspicious activities and potential security threats.

## Description

This Basic IDS provides real-time monitoring and alerting for various types of security threats including:

- **Network-based attacks**: DDoS attempts, port scans, suspicious port access, web application attacks
- **System log analysis**: Failed login attempts, brute force attacks, authentication failures, privilege escalation
- **System resource monitoring**: Unusual CPU/memory usage, suspicious process execution
- **Pattern matching**: Detection of common attack signatures and malicious payloads

The system is designed to be modular, allowing you to enable or disable specific monitoring components based on your needs.

## Features

- **Multi-threaded monitoring** of network, logs, and system resources
- **Real-time packet analysis** using Scapy for network traffic inspection
- **Log file monitoring** with pattern-based threat detection
- **System resource monitoring** with threshold-based alerting
- **Configurable thresholds** and monitoring parameters
- **JSON-based configuration** with command-line overrides
- **Comprehensive logging** with multiple severity levels
- **Modular design** allowing selective monitoring components

## Installation

### Prerequisites

- Python 3.6 or higher
- Root/Administrator privileges (required for network monitoring)

### Required Dependencies

Install the required Python packages:

```bash
pip install psutil scapy
```

### Optional System Dependencies

For better functionality on Linux systems:

```bash
# Ubuntu/Debian
sudo apt-get install python3-dev libpcap-dev

# CentOS/RHEL
sudo yum install python3-devel libpcap-devel

# macOS (with Homebrew)
brew install libpcap
```

### Installation Steps

1. Clone or download the script:
```bash
wget https://github.com/your-repo/basic-ids/raw/main/basic_ids.py
chmod +x basic_ids.py
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Create a configuration file:
```bash
python basic_ids.py --create-config ids_config.json
```

## Usage

### Basic Usage

Start the IDS with default settings:
```bash
sudo python basic_ids.py
```

### Advanced Usage Examples

**Monitor specific network interface:**
```bash
sudo python basic_ids.py --interface wlan0
```

**Monitor custom log files:**
```bash
sudo python basic_ids.py --log-files /var/log/auth.log /var/log/apache2/access.log
```

**Use configuration file:**
```bash
sudo python basic_ids.py --config ids_config.json
```

**Disable specific monitoring components:**
```bash
# Disable network monitoring (useful for testing without root)
python basic_ids.py --no-network

# Disable log monitoring
python basic_ids.py --no-logs

# Disable system monitoring
python basic_ids.py --no-system
```

**Adjust detection thresholds:**
```bash
sudo python basic_ids.py --threshold 50 --cpu-threshold 80 --memory-threshold 85
```

**Increase logging verbosity:**
```bash
sudo python basic_ids.py --log-level DEBUG
```

### Configuration File

Create a default configuration file:
```bash
python basic_ids.py --create-config my_config.json
```

Example configuration (`ids_config.json`):
```json
{
    "network_monitoring": true,
    "log_monitoring": true,
    "system_monitoring": true,
    "interface": "eth0",
    "threshold": 100,
    "log_files": [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/secure"
    ],
    "cpu_threshold": 90.0,
    "memory_threshold": 90.0,
    "log_level": "INFO",
    "log_file": "ids.log"
}
```

## Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--config, -c` | Configuration file path (JSON format) | None |
| `--interface, -i` | Network interface to monitor | eth0 |
| `--log-files, -l` | Log files to monitor | /var/log/auth.log /var/log/syslog |
| `--threshold, -t` | Packet threshold for DDoS detection | 100 |
| `--cpu-threshold` | CPU usage threshold percentage | 90.0 |
| `--memory-threshold` | Memory usage threshold percentage | 90.0 |
| `--log-level` | Logging level (DEBUG/INFO/WARNING/ERROR) | INFO |
| `--log-file` | Log file path | ids.log |
| `--create-config` | Create default configuration file and exit | None |
| `--no-network` | Disable network monitoring | False |
| `--no-logs` | Disable log monitoring | False |
| `--no-system` | Disable system monitoring | False |

## Detection Capabilities

### Network Monitoring
- **DDoS Detection**: Identifies high packet rates from single sources
- **Port Scanning**: Detects attempts to scan multiple ports
- **Suspicious Port Access**: Monitors access to commonly targeted ports
- **Web Attack Patterns**: SQL injection, XSS, directory traversal, command injection
- **Protocol Analysis**: Deep packet inspection for malicious content

### Log Analysis
- **Failed Login Attempts**: Tracks authentication failures
- **Brute Force Detection**: Identifies repeated failed login attempts
- **Invalid User Access**: Detects attempts to access non-existent accounts
- **Privilege Escalation**: Monitors sudo and su usage
- **Connection Monitoring**: Tracks refused connections and suspicious access

### System Monitoring
- **Resource Usage**: Monitors CPU and memory consumption
- **Process Monitoring**: Detects suspicious new processes
- **Baseline Comparison**: Compares current state against normal operation
- **Performance Anomalies**: Identifies unusual system behavior

## Output and Logging

The IDS generates output in multiple formats:

1. **Console Output**: Real-time alerts displayed on screen
2. **Log Files**: Structured logging with timestamps and severity levels
3. **Security Events**: Detailed event information with source IP and descriptions

### Log Format Example
```
2024-06-19 14:32:15,123 - WARNING - SECURITY ALERT: [2024-06-19 14:32:15.123456] HIGH - PORT_SCAN: Port scan detected: 15 ports accessed (Source: 192.168.1.100)
2024-06-19 14:33:02,456 - WARNING - SECURITY ALERT: [2024-06-19 14:33:02.456789] CRITICAL - BRUTE_FORCE_ATTACK: Brute force attack detected: 7 failed attempts (Source: 10.0.0.50)
```

### Alert Severity Levels
- **CRITICAL**: Immediate attention required (DDoS, brute force attacks)
- **HIGH**: Significant security concern (port scans, web attacks)
- **MEDIUM**: Suspicious activity requiring monitoring (failed logins, resource usage)
- **LOW**: Informational events

## Running as a Service

### Linux (systemd)

Create a systemd service file `/etc/systemd/system/basic-ids.service`:

```ini
[Unit]
Description=Basic Intrusion Detection System
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/basic-ids/basic_ids.py --config /etc/basic-ids/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable basic-ids
sudo systemctl start basic-ids
```

### Windows

Create a batch file `start_ids.bat`:
```batch
@echo off
cd /d "C:\path\to\basic-ids"
python basic_ids.py --config config.json
pause
```

Or use Task Scheduler to run the script automatically.

## Performance Considerations

- **Network Monitoring**: CPU intensive during high traffic periods
- **Log Monitoring**: Minimal resource usage, scales with log file size
- **System Monitoring**: Low overhead, checks every 30 seconds
- **Memory Usage**: Typically 50-200MB depending on traffic volume
- **Disk I/O**: Log writing and file position tracking

### Optimization Tips

1. Adjust monitoring intervals for your environment
2. Use specific network interfaces instead of monitoring all traffic
3. Limit log file monitoring to essential files
4. Tune detection thresholds based on normal traffic patterns
5. Consider log rotation to prevent disk space issues

## Troubleshooting

### Common Issues

**Permission Denied (Network Monitoring):**
```bash
# Solution: Run with root privileges
sudo python basic_ids.py
```

**Module Not Found (scapy/psutil):**
```bash
# Solution: Install missing dependencies
pip install scapy psutil
```

**No Network Interface Found:**
```bash
# Solution: List available interfaces and specify correct one
ip link show  # Linux
python -c "import psutil; print(psutil.net_if_addrs().keys())"  # Cross-platform
python basic_ids.py --interface wlan0
```

**Log Files Not Accessible:**
```bash
# Solution: Check file permissions and paths
ls -la /var/log/auth.log
sudo chmod 644 /var/log/auth.log  # If needed
```

**High CPU Usage:**
```bash
# Solution: Reduce monitoring frequency or disable network monitoring
python basic_ids.py --no-network  # Test without network monitoring
```

### Debug Mode

Enable debug logging for troubleshooting:
```bash
python basic_ids.py --log-level DEBUG
```

### Testing the IDS

Test different components to ensure proper functionality:

```bash
# Test log monitoring (generate failed login)
ssh invalid_user@localhost

# Test system monitoring (generate high CPU usage)
stress --cpu 4 --timeout 60s  # Requires stress tool

# Test network monitoring (port scan simulation)
nmap -sS localhost  # Requires nmap tool
```

## Security Considerations

### Important Security Notes

- **Root Privileges**: Network packet capture requires elevated privileges
- **Log File Access**: Ensure IDS has read access to monitored log files
- **False Positives**: Tune thresholds to reduce false alarms in your environment
- **Log Security**: Protect IDS log files from unauthorized access
- **Network Exposure**: Consider firewall rules for the monitoring system

### Best Practices

1. **Regular Updates**: Keep dependencies updated for security patches
2. **Configuration Security**: Protect configuration files with appropriate permissions
3. **Log Rotation**: Implement log rotation to prevent disk space exhaustion
4. **Backup Monitoring**: Monitor the IDS itself for failures
5. **Integration**: Consider integrating with SIEM or alerting systems

## Limitations

- **Encrypted Traffic**: Cannot inspect encrypted payloads (HTTPS, SSH, etc.)
- **High-Speed Networks**: May miss packets on very high-bandwidth connections
- **Advanced Attacks**: Detection limited to signature-based and threshold-based methods
- **False Positives**: May generate alerts for legitimate administrative activities
- **Resource Usage**: Network monitoring can be CPU intensive
- **Platform Specific**: Some features work better on Linux than Windows

## Integration Options

### SIEM Integration

The IDS can be integrated with Security Information and Event Management (SIEM) systems:

```python
# Example: Send alerts to syslog for SIEM consumption
import syslog

def send_to_siem(event):
    syslog.openlog("BasicIDS")
    syslog.syslog(syslog.LOG_ALERT, str(event))
    syslog.closelog()
```

### Email Alerts

Add email notification capability:

```python
import smtplib
from email.mime.text import MIMEText

def send_email_alert(event):
    # Configure SMTP settings
    smtp_server = "smtp.example.com"
    sender_email = "ids@example.com"
    receiver_email = "admin@example.com"
    
    msg = MIMEText(str(event))
    msg['Subject'] = f"Security Alert: {event.event_type}"
    msg['From'] = sender_email
    msg['To'] = receiver_email
    
    with smtplib.SMTP(smtp_server, 587) as server:
        server.starttls()
        server.login(sender_email, "password")
        server.send_message(msg)
```

### Webhook Integration

Send alerts to web services:

```python
import requests
import json

def send_webhook_alert(event):
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    payload = {
        "text": f"Security Alert: {event.event_type}",
        "attachments": [{
            "color": "danger",
            "fields": [
                {"title": "Source IP", "value": event.source_ip, "short": True},
                {"title": "Severity", "value": event.severity, "short": True},
                {"title": "Description", "value": event.description, "short": False}
            ]
        }]
    }
    requests.post(webhook_url, json=payload)
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure code follows PEP 8 style guidelines
5. Update documentation as needed
6. Submit a pull request

### Development Setup

```bash
git clone https://github.com/your-repo/basic-ids.git
cd basic-ids
pip install -r requirements-dev.txt
python -m pytest tests/
```

## License

MIT License

Copyright (c) 2024 Basic IDS Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Changelog

### Version 1.0.0 (2024-06-19)
- Initial release
- Network traffic monitoring with DDoS and port scan detection
- System log analysis with brute force detection
- System resource monitoring
- JSON configuration support
- Multi-threaded architecture
- Comprehensive logging and alerting

## Support

For support, questions, or feature requests:

- GitHub Issues: https://github.com/your-repo/basic-ids/issues
- Documentation: https://github.com/your-repo/basic-ids/wiki
- Security Issues: Please report privately to security@example.com

## Acknowledgments

- **Scapy**: Network packet manipulation library
- **psutil**: Cross-platform system and process utilities
- **Python Community**: For excellent documentation and libraries

## Disclaimer

This software is provided for educational and legitimate security monitoring purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse of this software.

Use this tool only on networks and systems that you own or have explicit permission to monitor. Unauthorized network monitoring may violate local laws and regulations.