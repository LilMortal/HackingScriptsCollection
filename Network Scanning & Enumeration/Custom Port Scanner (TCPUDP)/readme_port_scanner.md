# Custom Port Scanner (TCP/UDP)

A comprehensive network diagnostic tool for scanning TCP and UDP ports on target hosts. This tool is designed for legitimate network security testing, system administration, and network troubleshooting.

## Description

This port scanner provides:
- **TCP Port Scanning**: Fast, multi-threaded TCP port scanning with connection-based detection
- **UDP Port Scanning**: UDP port scanning with timeout-based detection
- **Service Detection**: Automatic identification of common services running on open ports
- **Flexible Port Specification**: Support for individual ports, port ranges, and comma-separated lists
- **Concurrent Scanning**: Multi-threaded scanning for improved performance
- **Detailed Reporting**: Comprehensive scan results with timing and statistics
- **Verbose Output**: Optional detailed output for debugging and analysis

## Features

- ✅ TCP and UDP port scanning
- ✅ Multi-threaded scanning for performance
- ✅ Hostname resolution and IP validation
- ✅ Service name detection
- ✅ Flexible port range specification
- ✅ Configurable timeouts and thread counts
- ✅ Progress tracking for large scans
- ✅ Comprehensive error handling
- ✅ Detailed scan summaries
- ✅ Command-line interface with argument validation

## Installation

### Requirements
- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

### Setup
1. Download the script:
```bash
wget https://raw.githubusercontent.com/yourusername/port-scanner/main/port_scanner.py
# or
curl -O https://raw.githubusercontent.com/yourusername/port-scanner/main/port_scanner.py
```

2. Make it executable (Linux/macOS):
```bash
chmod +x port_scanner.py
```

3. Run the script:
```bash
python3 port_scanner.py --help
```

## Usage

### Basic Syntax
```bash
python port_scanner.py -t <target> -p <ports> [options]
```

### Required Arguments
- `-t, --target`: Target IP address or hostname
- `-p, --ports`: Ports to scan (see port specification formats below)

### Optional Arguments
- `--tcp`: Scan TCP ports (default: enabled)
- `--udp`: Scan UDP ports (default: disabled)
- `--timeout`: Connection timeout in seconds (default: 3)
- `--threads`: Maximum number of concurrent threads (default: 100)
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Show help message

### Port Specification Formats

| Format | Example | Description |
|--------|---------|-------------|
| Single port | `80` | Scan port 80 |
| Multiple ports | `80,443,22` | Scan ports 80, 443, and 22 |
| Port range | `1-1000` | Scan ports 1 through 1000 |
| Mixed format | `22,80-90,443` | Scan port 22, ports 80-90, and port 443 |

## Examples

### Basic TCP Scan
```bash
# Scan common ports on a target
python port_scanner.py -t 192.168.1.1 -p 80,443,22,21,25,53,110,143

# Scan port range
python port_scanner.py -t example.com -p 1-1000
```

### UDP Scanning
```bash
# Scan UDP ports only
python port_scanner.py -t 192.168.1.1 -p 53,67,68,123,161 --udp

# Scan both TCP and UDP
python port_scanner.py -t 10.0.0.1 -p 80,443,53,123 --tcp --udp
```

### Advanced Options
```bash
# Fast scan with high thread count and low timeout
python port_scanner.py -t 192.168.1.0/24 -p 1-65535 --timeout 1 --threads 200

# Verbose scan with detailed output
python port_scanner.py -t localhost -p 1-1000 --verbose

# Comprehensive scan
python port_scanner.py -t example.com -p 1-65535 --tcp --udp --timeout 5 --threads 50 --verbose
```

### Practical Use Cases

#### Web Server Testing
```bash
python port_scanner.py -t webserver.example.com -p 80,443,8080,8443
```

#### Network Infrastructure Discovery
```bash
python port_scanner.py -t 192.168.1.1 -p 22,23,53,80,443,161,162,514
```

#### Database Server Scanning
```bash
python port_scanner.py -t dbserver.local -p 1433,1521,3306,5432,5984,6379,27017
```

#### Mail Server Analysis
```bash
python port_scanner.py -t mailserver.com -p 25,110,143,465,587,993,995
```

## Output Format

### Scan Progress
```
Starting TCP scan on 192.168.1.1
Scanning 1000 ports with 100 threads
Timeout: 3 seconds
--------------------------------------------------
Port 22/tcp: open (ssh)
Port 80/tcp: open (http)
Port 443/tcp: open (https)
Progress: 1000/1000 (100.0%)

Scan completed in 12.34 seconds
```

### Summary Report
```
============================================================
SCAN SUMMARY FOR 192.168.1.1
============================================================

OPEN PORTS (3):
------------------------------
22/tcp (ssh)
80/tcp (http)
443/tcp (https)

Total ports scanned: 1000
Open ports: 3
Closed ports: 995
Filtered/Error ports: 2
```

## Performance Considerations

### Thread Count Guidelines
- **Small scans (< 100 ports)**: 10-50 threads
- **Medium scans (100-1000 ports)**: 50-150 threads
- **Large scans (> 1000 ports)**: 100-300 threads
- **Very large scans (> 10000 ports)**: 200-500 threads

### Timeout Settings
- **Local network**: 1-2 seconds
- **Internet hosts**: 3-5 seconds
- **Slow connections**: 5-10 seconds

### Memory Usage
The scanner uses minimal memory, typically:
- Base usage: ~10-20 MB
- Per thread: ~1-2 MB
- Large port lists: Additional ~1 MB per 10,000 ports

## Ethical Use and Legal Considerations

### ⚠️ IMPORTANT WARNINGS

**This tool is intended for legitimate purposes only:**
- Network security testing on your own systems
- System administration and troubleshooting
- Penetration testing with proper authorization
- Educational purposes in controlled environments

### Legal Requirements
- **Only scan networks you own or have explicit permission to test**
- Unauthorized port scanning may violate:
  - Computer Fraud and Abuse Act (CFAA) in the US
  - Computer Misuse Act in the UK
  - Similar laws in other jurisdictions
- Always obtain written permission before scanning third-party systems
- Respect rate limits and avoid overwhelming target systems

### Best Practices
- Use appropriate thread counts to avoid overwhelming targets
- Scan during appropriate hours to minimize disruption
- Document your testing activities
- Inform network administrators of your testing activities
- Use the tool responsibly and professionally

## Troubleshooting

### Common Issues

#### "Permission denied" errors
```bash
# Run with appropriate privileges for low-numbered ports
sudo python port_scanner.py -t localhost -p 1-1024
```

#### "Name resolution failed"
```bash
# Verify hostname/IP address
nslookup example.com
# or use IP address directly
python port_scanner.py -t 8.8.8.8 -p 53
```

#### Slow scanning performance
```bash
# Reduce timeout and increase threads
python port_scanner.py -t target -p 1-1000 --timeout 1 --threads 200
```

#### UDP scan showing no results
UDP scanning is inherently less reliable than TCP. Consider:
- Increasing timeout values
- Running multiple scans
- Verifying target actually has UDP services

### Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "Failed to resolve hostname" | DNS resolution failed | Check hostname or use IP address |
| "Invalid port numbers" | Port outside 1-65535 range | Use valid port range |
| "Connection refused" | Port closed or filtered | Normal behavior for closed ports |
| "Timeout" | No response within timeout | Increase timeout or check connectivity |

## Technical Details

### TCP Scanning Method
The scanner uses the TCP SYN connection method:
1. Create socket with specified timeout
2. Attempt connection to target:port
3. Classify result based on response:
   - Connection successful = Open port
   - Connection refused = Closed port
   - Timeout = Filtered port

### UDP Scanning Method
UDP scanning is more complex due to protocol characteristics:
1. Send empty UDP packet to target:port
2. Wait for response within timeout period
3. Classify based on response:
   - Response received = Open port
   - ICMP "Port Unreachable" = Closed port
   - No response = Open or filtered

### Threading Model
- Uses ThreadPoolExecutor for concurrent scanning
- Thread-safe result collection with locks
- Configurable thread pool size
- Automatic workload distribution

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup
```bash
git clone https://github.com/yourusername/port-scanner.git
cd port-scanner
python -m pytest tests/  # Run tests
```

## License

This project is licensed under the MIT License - see below for details:

```
MIT License

Copyright (c) 2024 Port Scanner Project

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
```

## Changelog

### Version 1.0.0
- Initial release with TCP and UDP scanning
- Multi-threaded scanning support
- Service detection
- Comprehensive error handling
- Command-line interface

## Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Check existing documentation
- Review troubleshooting section

---

**Remember: Use this tool responsibly and only on networks you own or have explicit permission to test.**
