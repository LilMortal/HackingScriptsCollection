# ARP Scanner

A fast, efficient Python-based ARP scanner for discovering active devices on local networks. This tool sends ARP (Address Resolution Protocol) requests to identify devices that are currently online and retrieves their MAC addresses.

## Features

- **Fast Multi-threaded Scanning**: Uses concurrent threads for rapid network discovery
- **Flexible Target Specification**: Supports CIDR notation, IP ranges, and single IP addresses
- **Multiple Output Formats**: Save results in text or JSON format
- **Progress Tracking**: Real-time scan progress with device discovery notifications
- **Configurable Parameters**: Adjustable timeouts and thread counts
- **Error Handling**: Robust error handling and input validation
- **Cross-platform**: Works on Linux, macOS, and Windows

## Installation

### Prerequisites

- Python 3.6 or higher
- Administrative/root privileges (required for sending raw network packets)

### Install Dependencies

```bash
pip install scapy
```

Or using pip3:
```bash
pip3 install scapy
```

For system-wide installation on Linux/macOS:
```bash
sudo pip3 install scapy
```

### Download the Script

Save the `arp_scanner.py` script to your desired directory and make it executable:

```bash
chmod +x arp_scanner.py
```

## Usage

### Basic Usage

```bash
# Scan entire subnet
python3 arp_scanner.py -t 192.168.1.0/24

# Scan IP range
python3 arp_scanner.py -t 192.168.1.1-192.168.1.100

# Scan single IP
python3 arp_scanner.py -t 192.168.1.1

# Scan range using separate arguments
python3 arp_scanner.py -r 192.168.1.1 192.168.1.254
```

### Advanced Usage

```bash
# Save results to file
python3 arp_scanner.py -t 192.168.1.0/24 -o results.txt

# Save results in JSON format
python3 arp_scanner.py -t 192.168.1.0/24 -o results.json --format json

# Custom timeout and thread count
python3 arp_scanner.py -t 192.168.1.0/24 --timeout 2 -j 30

# Quiet mode (suppress progress output)
python3 arp_scanner.py -t 192.168.1.0/24 -q
```

### Command-Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `-t, --target` | Target network, IP range, or single IP | `-t 192.168.1.0/24` |
| `-r, --range` | IP range as two separate arguments | `-r 192.168.1.1 192.168.1.100` |
| `-o, --output` | Output file to save results | `-o scan_results.txt` |
| `--format` | Output format (txt or json) | `--format json` |
| `--timeout` | ARP request timeout in seconds | `--timeout 2.0` |
| `-j, --threads` | Maximum concurrent threads (1-200) | `-j 30` |
| `-q, --quiet` | Suppress progress output | `-q` |
| `-h, --help` | Show help message | `-h` |

## Examples

### Example 1: Basic Subnet Scan
```bash
python3 arp_scanner.py -t 192.168.1.0/24
```

Output:
```
Scanning 254 IP addresses...
Target: 192.168.1.0/24
--------------------------------------------------
Progress: 10/254 (3.9%)
Found device: 192.168.1.1 -> aa:bb:cc:dd:ee:ff
Progress: 20/254 (7.9%)
Found device: 192.168.1.100 -> 11:22:33:44:55:66
...
==================================================
Scan completed! Found 3 active devices:
==================================================
IP Address      MAC Address
-----------------------------------
192.168.1.1     aa:bb:cc:dd:ee:ff
192.168.1.100   11:22:33:44:55:66
192.168.1.200   77:88:99:aa:bb:cc
```

### Example 2: Save Results to JSON
```bash
python3 arp_scanner.py -t 192.168.1.0/24 -o network_scan.json --format json
```

Creates a JSON file with:
```json
{
  "scan_time": "2025-06-21 14:30:15",
  "total_devices": 3,
  "devices": [
    {
      "ip": "192.168.1.1",
      "mac": "aa:bb:cc:dd:ee:ff"
    },
    {
      "ip": "192.168.1.100",
      "mac": "11:22:33:44:55:66"
    }
  ]
}
```

## Platform-Specific Notes

### Linux
- Requires root privileges: `sudo python3 arp_scanner.py -t 192.168.1.0/24`
- Install scapy system-wide: `sudo pip3 install scapy`

### macOS
- Requires root privileges: `sudo python3 arp_scanner.py -t 192.168.1.0/24`
- May need to install with: `sudo pip3 install scapy`

### Windows
- Run Command Prompt or PowerShell as Administrator
- Install scapy: `pip install scapy`
- May require WinPcap or Npcap for packet capture

## Troubleshooting

### Permission Errors
If you encounter permission errors:
```bash
# Linux/macOS
sudo python3 arp_scanner.py -t 192.168.1.0/24

# Windows (run as Administrator)
python arp_scanner.py -t 192.168.1.0/24
```

### Scapy Installation Issues
```bash
# If pip install fails, try:
pip install --user scapy

# On some systems:
python -m pip install scapy

# For development version:
pip install git+https://github.com/secdev/scapy.git
```

### No Devices Found
- Verify you're scanning the correct network range
- Check if devices have ARP disabled or are behind a firewall
- Try increasing the timeout: `--timeout 3`
- Reduce thread count for more reliable scanning: `-j 10`

## Ethical Use and Legal Considerations

⚠️ **Important**: This tool should only be used on networks you own or have explicit permission to scan.

### Legal Use Cases
- Network administration and troubleshooting
- Security auditing of your own networks
- Educational purposes in controlled environments
- Asset discovery in corporate environments (with authorization)

### Prohibited Uses
- Scanning networks without permission
- Reconnaissance for malicious purposes
- Violating terms of service or network policies
- Any illegal network scanning activities

### Best Practices
- Always obtain proper authorization before scanning
- Be mindful of network impact with large scans
- Respect rate limits and avoid overwhelming networks
- Document and report findings appropriately
- Follow your organization's security policies

## Limitations

- Only works on local network segments (same broadcast domain)
- Cannot detect devices that don't respond to ARP requests
- May be blocked by firewalls or security software
- Requires administrative privileges
- Performance depends on network size and device response times

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- Feature enhancements
- Documentation improvements
- Platform-specific optimizations

## License

This project is licensed under the MIT License:

```
MIT License

Copyright (c) 2025 ARP Scanner

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

## Support

For issues, questions, or feature requests, please:
1. Check the troubleshooting section above
2. Review existing GitHub issues
3. Create a new issue with detailed information about your problem

---

**Version**: 1.0.0  
**Last Updated**: June 2025  
**Python Compatibility**: 3.6+
