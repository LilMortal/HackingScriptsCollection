# SNMP Enumerator

A comprehensive Python-based SNMP enumeration tool designed for legitimate network administration and security testing purposes. This tool allows network administrators and security professionals to gather system information, network interfaces, and other valuable data from SNMP-enabled devices.

## Features

- **Multi-target scanning**: Support for single IPs and CIDR ranges
- **Community string testing**: Test multiple SNMP community strings
- **System information gathering**: Collect device details like system description, uptime, contact info
- **Network interface enumeration**: Discover and analyze network interfaces
- **TCP connection monitoring**: Optional TCP connection table enumeration
- **Concurrent scanning**: Multi-threaded scanning for improved performance
- **Multiple SNMP versions**: Support for SNMP v1, v2c, and v3
- **Flexible output**: Clean, formatted results with optional quiet mode
- **Error handling**: Robust error handling and timeout management

## Description

The SNMP Enumerator queries SNMP-enabled devices to collect valuable network information including:

- System description and identification
- Device uptime and location
- Contact information
- Network interface details (MAC addresses, IP addresses, status)
- TCP connection tables (optional)
- System services information

This tool is particularly useful for:
- Network inventory and documentation
- Security assessments and penetration testing
- Network troubleshooting and monitoring
- Device discovery and profiling

## Installation

### Prerequisites

This script requires Python 3.6+ and the net-snmp tools to be installed on your system.

#### Install net-snmp tools:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install snmp snmp-mibs-downloader
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install net-snmp-utils
# or for newer versions:
sudo dnf install net-snmp-utils
```

**macOS:**
```bash
brew install net-snmp
```

**Windows:**
Download and install net-snmp from the official website or use a package manager like Chocolatey:
```bash
choco install net-snmp
```

#### Install Python dependencies:

The script uses only Python standard libraries, so no additional Python packages are required.

### Download and Setup

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/yourrepo/snmp-enumerator/main/snmp_enumerator.py
```

2. Make it executable:
```bash
chmod +x snmp_enumerator.py
```

3. Verify installation:
```bash
python3 snmp_enumerator.py --help
```

## Usage

### Basic Usage

```bash
# Scan a single host with default community string
python3 snmp_enumerator.py -t 192.168.1.1

# Scan with specific community strings
python3 snmp_enumerator.py -t 192.168.1.1 -c public private community

# Scan a network range
python3 snmp_enumerator.py -t 192.168.1.0/24 -c public
```

### Advanced Usage

```bash
# Use SNMP v1 with custom timeout
python3 snmp_enumerator.py -t 192.168.1.1 -c public -v 1 --timeout 5

# Skip interface enumeration, include TCP connections
python3 snmp_enumerator.py -t 192.168.1.1 -c public --no-interfaces --tcp

# Concurrent scanning with custom thread count
python3 snmp_enumerator.py -t 192.168.1.0/24 -c public --threads 20

# Quiet mode for scripting
python3 snmp_enumerator.py -t 192.168.1.1 -c public --quiet
```

### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--target` | `-t` | Target IP address or CIDR range | Required |
| `--communities` | `-c` | SNMP community strings to test | `public` |
| `--version` | `-v` | SNMP version (1, 2c, 3) | `2c` |
| `--timeout` | | SNMP timeout in seconds | `2` |
| `--retries` | | Number of retries for failed queries | `1` |
| `--threads` | | Number of concurrent threads | `5` |
| `--no-interfaces` | | Skip network interface enumeration | `False` |
| `--tcp` | | Include TCP connection enumeration | `False` |
| `--quiet` | | Suppress banner and verbose output | `False` |

## Examples

### Example 1: Basic Host Scan
```bash
python3 snmp_enumerator.py -t 192.168.1.1 -c public
```

**Output:**
```
============================================================
SNMP Enumeration Results for 192.168.1.1
Timestamp: 2025-06-21 14:30:15
============================================================
✅ SNMP accessible with community: 'public'

📋 System Information:
------------------------------
  sysDescr: Linux router 4.19.0 #1 SMP x86_64
  sysName: router.local
  sysUpTime: 15 days, 3:24:17
  sysContact: admin@company.com
  sysLocation: Data Center Room 1
```

### Example 2: Network Range Scan
```bash
python3 snmp_enumerator.py -t 192.168.1.0/24 -c public private --threads 10
```

### Example 3: Detailed Interface Analysis
```bash
python3 snmp_enumerator.py -t 192.168.1.1 -c public --tcp --timeout 3
```

## Security and Ethical Considerations

### ⚠️ Important Security Notes

- **Authorization Required**: Only use this tool on networks and devices you own or have explicit written permission to test
- **Legitimate Use Only**: This tool is designed for legitimate network administration, security testing, and educational purposes
- **Responsible Disclosure**: If you discover vulnerabilities during testing, follow responsible disclosure practices
- **Legal Compliance**: Ensure your use complies with local laws and regulations

### Common SNMP Security Issues

This tool may help identify:
- Default or weak community strings
- Excessive information disclosure
- Misconfigured SNMP services
- Unencrypted SNMP communications

### Recommendations

- Use SNMPv3 with encryption when possible
- Change default community strings
- Implement SNMP access control lists (ACLs)
- Monitor SNMP access logs
- Limit SNMP information exposure

## Troubleshooting

### Common Issues

**1. "SNMP tools not found" error:**
- Install net-snmp utilities as described in the installation section
- Ensure `snmpget` and `snmpwalk` are in your system PATH

**2. No SNMP responses:**
- Verify the target device has SNMP enabled
- Check firewall rules (SNMP uses UDP port 161)
- Try different community strings
- Verify network connectivity

**3. Timeout errors:**
- Increase timeout value with `--timeout`
- Check network latency and packet loss
- Verify SNMP service is running on target

**4. Permission denied:**
- Ensure you have permission to scan the target network
- Check if SNMP access is restricted by IP address

### Debug Mode

For debugging issues, you can manually test SNMP connectivity:

```bash
# Test basic SNMP connectivity
snmpget -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.1.0

# Test SNMP walk
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1
```

## Output Format

The tool provides structured output including:

- **Target Information**: IP address and scan timestamp
- **SNMP Access Status**: Whether SNMP is accessible and which community string worked
- **System Information**: Device details, uptime, contact information
- **Network Interfaces**: Interface details, MAC addresses, status
- **TCP Connections**: Active connections (if requested)
- **Scan Summary**: Overall statistics

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure code follows PEP 8 style guidelines
5. Submit a pull request with a clear description

## Changelog

### Version 1.0.0
- Initial release
- Basic SNMP enumeration functionality
- Support for multiple targets and community strings
- Network interface and TCP connection enumeration
- Multi-threaded scanning capability

## License

MIT License

Copyright (c) 2025 SNMP Enumerator

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

## Disclaimer

This tool is provided for educational and legitimate network administration purposes only. The authors are not responsible for any misuse of this tool. Users are solely responsible for ensuring they have proper authorization before scanning any networks or devices.

## Support

For support, bug reports, or feature requests:

1. Check the troubleshooting section above
2. Search existing issues on the project repository
3. Create a new issue with detailed information including:
   - Operating system and version
   - Python version
   - Complete error messages
   - Steps to reproduce the issue

## Related Tools

- **nmap**: Network discovery and security auditing
- **snmp-check**: Perl-based SNMP enumerator
- **onesixtyone**: Fast SNMP scanner
- **snmpwalk**: Command-line SNMP application

## References

- [RFC 1157 - Simple Network Management Protocol (SNMP)](https://tools.ietf.org/html/rfc1157)
- [RFC 3416 - Version 2 of the Protocol Operations for SNMP](https://tools.ietf.org/html/rfc3416)
- [Net-SNMP Documentation](http://www.net-snmp.org/docs/)
- [SNMP OID Reference](https://www.oid-info.com/)

---

**Remember**: Always use this tool responsibly and ethically. Ensure you have proper authorization before scanning networks you do not own.
