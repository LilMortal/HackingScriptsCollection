# OS Detection Tool (TTL/Window Size)

A Python-based network reconnaissance tool that performs operating system detection by analyzing TTL (Time To Live) values from ICMP ping responses and TCP connection characteristics. This tool is designed for network administrators and cybersecurity professionals to identify operating systems of remote hosts.

## Features

- **TTL-based OS Detection**: Analyzes ICMP ping TTL values to identify operating systems
- **TCP Port Scanning**: Scans common ports to gather additional OS fingerprinting data
- **Multi-threading**: Concurrent scanning for improved performance
- **Multiple Target Support**: Scan single hosts, multiple hosts, or load targets from file
- **IP Range Support**: Basic IP range scanning (e.g., 192.168.1.1-192.168.1.10)
- **Confidence Scoring**: Provides confidence levels for OS detection results
- **Verbose Mode**: Detailed output for debugging and analysis
- **Cross-platform**: Works on Windows, Linux, and macOS

## Installation

### Prerequisites

- Python 3.6 or higher
- Network connectivity to target hosts
- Administrative privileges may be required for ICMP ping operations on some systems

### Dependencies

This tool uses only Python standard libraries:
- `socket` - Network operations
- `subprocess` - System command execution
- `threading` and `concurrent.futures` - Multi-threading support
- `argparse` - Command-line argument parsing
- `ipaddress` - IP address validation and manipulation
- `re` - Regular expression matching

### Installation Steps

1. **Clone or download the script:**
   ```bash
   wget https://example.com/os_detection.py
   # or
   curl -O https://example.com/os_detection.py
   ```

2. **Make the script executable (Linux/macOS):**
   ```bash
   chmod +x os_detection.py
   ```

3. **Verify Python installation:**
   ```bash
   python3 --version
   ```

## Usage

### Basic Usage

```bash
# Scan a single host
python3 os_detection.py -t 192.168.1.1

# Scan a hostname
python3 os_detection.py -t google.com

# Scan with specific ports
python3 os_detection.py -t 192.168.1.1 -p 22,80,443

# Scan with verbose output
python3 os_detection.py -t 192.168.1.1 -v
```

### Advanced Usage

```bash
# Scan multiple targets from file
python3 os_detection.py -f targets.txt

# Scan IP range (basic support)
python3 os_detection.py -t 192.168.1.1-192.168.1.10

# Custom port range and timeout
python3 os_detection.py -t 192.168.1.1 -p 1-1000 --timeout 5

# Scan specific service ports
python3 os_detection.py -t target.com -p 21,22,23,53,80,110,143,443,993,995
```

### Command-Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `-t, --target` | Target host (IP or hostname) | `-t 192.168.1.1` |
| `-f, --file` | File with target list (one per line) | `-f targets.txt` |
| `-p, --ports` | Ports to scan (comma-separated, ranges supported) | `-p 22,80,443` or `-p 1-100` |
| `--timeout` | Network operation timeout in seconds (default: 3) | `--timeout 5` |
| `-v, --verbose` | Enable verbose output | `-v` |
| `--version` | Show version information | `--version` |

### Target File Format

Create a text file with one target per line:

```
# targets.txt
192.168.1.1
192.168.1.10
google.com
github.com
# Comments are supported
10.0.0.1
```

## How It Works

### TTL Analysis

The tool analyzes TTL (Time To Live) values from ICMP ping responses. Different operating systems use different default TTL values:

- **Linux/Unix/Android/macOS**: TTL 64
- **Windows**: TTL 128
- **Cisco/FreeBSD/OpenBSD**: TTL 255
- **Older systems**: Various values (32, 30, 60)

The tool accounts for network hops that decrease TTL values and attempts to determine the original TTL.

### TCP Fingerprinting

Additional OS detection is performed by:
- Analyzing open TCP ports (service-based OS hints)
- Connection timing analysis
- TCP window size analysis (when available)

### Port-Based Detection

Certain open ports provide strong OS indicators:
- **Port 3389 (RDP)**: Strong Windows indicator
- **Port 22 (SSH)**: Common on Linux/Unix systems
- **Ports 135, 139, 445**: Windows networking services
- **Port combinations**: Different OS distributions favor different service combinations

### Confidence Scoring

The tool provides confidence levels based on:
- **High**: Multiple consistent indicators (4+ votes)
- **Medium**: Some consistent indicators (2-3 votes)
- **Low**: Limited or conflicting indicators (1 vote)
- **Unknown**: No reliable indicators

## Sample Output

```
OS Detection Tool v1.0
Scanning 1 target(s)
Ports: 22,23,53,80,135,139,443,445,993,995,3389
Timeout: 3 seconds

============================================================
Target: 192.168.1.1
============================================================
ICMP Ping:
  Response Time: 1.23 ms
  TTL: 64
  OS Candidates (TTL): Linux, Unix, Android, macOS

Open TCP Ports:
  Port 22: Open (2.1 ms)
  Port 80: Open (1.8 ms)
  Port 443: Open (2.3 ms)

OS Detection Summary:
  Best Guess: Linux
  Confidence: High
  Vote Breakdown:
    Linux: 4 votes
    Unix: 2 votes
    macOS: 2 votes
```

## Limitations

1. **Network Firewalls**: Firewalls may block ICMP or filter TCP connections
2. **NAT/Proxy**: Network address translation can affect TTL values
3. **False Positives**: Some embedded devices may mimic common OS signatures
4. **Modern Security**: Many systems implement TTL randomization or other anti-fingerprinting measures
5. **Platform Restrictions**: Some features may require administrative privileges
6. **Network Routing**: Complex routing can affect TTL analysis accuracy

## Ethical Use and Legal Considerations

### ⚠️ Important Warnings

- **Authorization Required**: Only scan networks and systems you own or have explicit permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: If vulnerabilities are discovered, follow responsible disclosure practices
- **Educational Purpose**: This tool is intended for educational and legitimate security testing purposes only

### Recommended Use Cases

- Network inventory and asset management
- Security assessments with proper authorization
- Educational cybersecurity training
- Penetration testing engagements
- Network troubleshooting and diagnostics

## Troubleshooting

### Common Issues

1. **Permission Denied for ICMP**:
   ```bash
   # Linux/macOS - run with sudo if needed
   sudo python3 os_detection.py -t target.com
   ```

2. **DNS Resolution Failures**:
   ```bash
   # Use IP address instead of hostname
   python3 os_detection.py -t 8.8.8.8
   ```

3. **Timeout Issues**:
   ```bash
   # Increase timeout for slow networks
   python3 os_detection.py -t target.com --timeout 10
   ```

4. **No Results Returned**:
   - Check network connectivity
   - Verify target is reachable
   - Try different ports
   - Enable verbose mode for debugging

### Performance Optimization

- Use focused port lists instead of large ranges
- Adjust timeout values based on network conditions
- Consider network load when scanning multiple targets
- Use IP addresses instead of hostnames when possible to avoid DNS lookups

## Contributing

Contributions are welcome! Areas for improvement:

- Additional OS signatures and fingerprints
- Enhanced TCP window size analysis
- IPv6 support
- More sophisticated timing analysis
- Integration with external OS detection databases
- GUI interface

## License

MIT License

Copyright (c) 2024 OS Detection Tool

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

### Version 1.0 (Initial Release)
- TTL-based OS detection
- TCP port scanning
- Multi-target support
- IP range scanning (basic)
- Confidence scoring system
- Cross-platform compatibility
- Comprehensive error handling

## Support

For issues, questions, or contributions:
- Create an issue in the project repository
- Review the troubleshooting section
- Check that you have the required permissions
- Verify network connectivity to targets

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems. The authors are not responsible for any misuse of this software or any damages that may result from its use.
