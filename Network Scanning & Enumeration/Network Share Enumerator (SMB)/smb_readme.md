# Network Share Enumerator (SMB)

A Python script for enumerating SMB shares on network hosts. This tool is designed for legitimate network administration, security assessment, and penetration testing purposes.

## Description

The SMB Enumerator discovers and lists SMB (Server Message Block) shares on network hosts by:

- Scanning for open SMB ports (139, 445)
- Enumerating available shares using smbclient
- Gathering NetBIOS information when available
- Supporting both authenticated and unauthenticated enumeration
- Providing concurrent scanning for improved performance

## Features

- **Multi-target Support**: Scan single IPs, CIDR ranges, or load targets from file
- **Authentication Options**: Support for username/password authentication or null sessions
- **Concurrent Scanning**: Multi-threaded scanning for improved performance
- **Comprehensive Output**: Detailed information about shares, types, and comments
- **NetBIOS Information**: Attempts to gather NetBIOS computer names
- **Flexible Output**: Console display and file output options
- **Error Handling**: Robust error handling and timeout management

## Installation

### Prerequisites

This script requires the `smbclient` utility to be installed on your system.

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install samba-client
```

**CentOS/RHEL:**
```bash
sudo yum install samba-client
```

**Fedora:**
```bash
sudo dnf install samba-client
```

**macOS (using Homebrew):**
```bash
brew install samba
```

### Python Requirements

The script uses only Python standard libraries, so no additional Python packages are required. However, ensure you have Python 3.6 or later installed.

### Download and Setup

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/yourusername/smb-enumerator/main/smb_enumerator.py
```

2. Make it executable:
```bash
chmod +x smb_enumerator.py
```

## Usage

### Basic Usage

```bash
# Scan a single host
python3 smb_enumerator.py -t 192.168.1.100

# Scan a CIDR range
python3 smb_enumerator.py -t 192.168.1.0/24

# Scan with authentication
python3 smb_enumerator.py -t 192.168.1.100 -u username -p password

# Scan targets from file
python3 smb_enumerator.py -f targets.txt
```

### Advanced Usage

```bash
# Scan with custom timeout and thread count
python3 smb_enumerator.py -t 10.0.0.0/8 --timeout 10 --threads 100

# Save results to file
python3 smb_enumerator.py -t 192.168.1.0/24 -o scan_results.txt

# Use null session (no authentication)
python3 smb_enumerator.py -t 192.168.1.100 --no-auth

# Verbose output
python3 smb_enumerator.py -t 192.168.1.100 -v
```

### Command Line Options

```
Target Specification:
  -t, --target          Target IP address or CIDR range
  -f, --file           File containing list of targets (one per line)

Authentication:
  -u, --username       Username for SMB authentication
  -p, --password       Password for SMB authentication
  --no-auth           Skip authentication (use null session)

Scan Options:
  --timeout           Connection timeout in seconds (default: 3)
  --threads           Maximum number of concurrent threads (default: 50)

Output Options:
  -o, --output        Save results to file
  -v, --verbose       Enable verbose output
```

### Target File Format

When using the `-f` option, create a text file with one target per line:

```
192.168.1.100
192.168.2.0/24
10.0.0.50
# This is a comment and will be ignored
172.16.1.0/28
```

## Output Format

The script provides detailed output including:

- **Host Information**: IP address and open SMB ports
- **NetBIOS Details**: Computer name and server service information
- **Share Enumeration**: Share names, types, and comments
- **Summary Statistics**: Total hosts scanned, accessible hosts, and shares found

### Example Output

```
[*] Starting SMB enumeration on 5 targets...
[*] Timeout: 3s, Max threads: 50
[+] 192.168.1.100 - SMB accessible (3 shares)
[-] 192.168.1.101 - No SMB access
[+] 192.168.1.102 - SMB accessible (5 shares)

============================================================
SMB SHARE ENUMERATION RESULTS
============================================================

[+] Host: 192.168.1.100
    SMB Ports: 139, 445
    NetBIOS Info:
      computer_name: FILESERVER01
    Shares (3):
      - ADMIN$ (Disk)
        Comment: Remote Admin
      - C$ (Disk)
        Comment: Default share
      - SharedFiles (Disk)
        Comment: Company shared files

[*] Scan completed in 12.34 seconds
[*] 2/5 hosts with SMB access
[*] 8 total shares discovered
```

## Security Considerations

### Ethical Use

This tool is intended for legitimate purposes only:

- **Network Administration**: Inventory and manage SMB shares
- **Security Assessment**: Authorized penetration testing and security audits
- **Compliance**: Verify security policies and access controls

### Important Notes

- **Authorization Required**: Only use this tool on networks you own or have explicit permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: If vulnerabilities are found, follow responsible disclosure practices
- **Log Monitoring**: Be aware that SMB enumeration activities may be logged by target systems

### Limitations

- Requires `smbclient` to be installed on the scanning system
- Performance depends on network latency and target responsiveness
- Some shares may require specific authentication or may be hidden
- Firewalls and intrusion detection systems may block or detect scanning activities

## Troubleshooting

### Common Issues

**"smbclient not found" Error:**
- Install the samba-client package as described in the installation section

**Connection Timeouts:**
- Increase timeout value with `--timeout` option
- Check network connectivity and firewall rules

**Authentication Failures:**
- Verify username and password are correct
- Try using `--no-auth` for null session access
- Check if target requires specific authentication methods

**Permission Denied:**
- Ensure you have permission to scan the target networks
- Some shares may require administrative privileges

### Performance Tuning

- Adjust `--threads` based on your system capabilities and network conditions
- Increase `--timeout` for slow networks or overloaded targets
- Use smaller CIDR ranges to reduce scan time

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Submit a pull request with a clear description

## License

This project is licensed under the MIT License - see the LICENSE file for details.

```
MIT License

Copyright (c) 2024 Network Security Team

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

## Version History

- **v1.0** - Initial release with basic SMB enumeration functionality

## Contact

For questions, suggestions, or bug reports, please open an issue on the project repository.

---

**Disclaimer**: This tool is provided for educational and legitimate security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems.
