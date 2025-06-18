# Default Credentials Scanner

A comprehensive security assessment tool designed to identify systems using default credentials across multiple services. This tool is intended for authorized penetration testing and vulnerability assessment activities.

## ⚠️ IMPORTANT DISCLAIMER

**This tool is for authorized security testing only!** 

- Only use this tool on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal in most jurisdictions
- The authors are not responsible for any misuse of this tool
- Always follow responsible disclosure practices for any vulnerabilities found

## Description

The Default Credentials Scanner is a multi-threaded Python tool that tests common default username/password combinations against various network services. It supports SSH, HTTP, Telnet, and FTP services and can scan individual hosts, IP ranges, or lists of targets from files.

### Key Features

- **Multi-service support**: SSH, HTTP Basic Auth, Telnet, and FTP
- **Flexible target specification**: Single IPs, CIDR ranges, or target files
- **Multi-threaded scanning**: Configurable number of concurrent threads
- **Comprehensive credential database**: Built-in database of common default credentials
- **Multiple output formats**: JSON and text output options
- **Detailed logging**: Verbose mode with timestamp logging
- **Port validation**: Automatic port accessibility checking
- **Error handling**: Robust error handling and timeout management

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Required Dependencies

Install the required Python packages:

```bash
pip install paramiko requests
```

Or install from requirements file:

```bash
pip install -r requirements.txt
```

#### requirements.txt
```
paramiko>=2.7.0
requests>=2.25.0
```

### System Requirements

- Linux, macOS, or Windows
- Network connectivity to target systems
- Sufficient privileges to create network connections

## Usage

### Basic Usage

```bash
# Scan a single target with default ports and services
python default_creds_scanner.py -t 192.168.1.100

# Scan multiple targets
python default_creds_scanner.py -t 192.168.1.100 192.168.1.101 192.168.1.102

# Scan a network range
python default_creds_scanner.py -t 192.168.1.0/24

# Scan specific ports
python default_creds_scanner.py -t 192.168.1.100 -p 22,80,443,8080

# Scan specific services
python default_creds_scanner.py -t 192.168.1.100 -s ssh,http

# Use a target file
python default_creds_scanner.py -f targets.txt
```

### Advanced Usage

```bash
# Increase timeout and threads for faster scanning
python default_creds_scanner.py -t 192.168.1.0/24 --timeout 5 --threads 10

# Enable verbose output
python default_creds_scanner.py -t 192.168.1.100 -v

# Save results to JSON file
python default_creds_scanner.py -t 192.168.1.100 -o results.json

# Save results to text file
python default_creds_scanner.py -t 192.168.1.100 -o results.txt --format txt

# Comprehensive scan with all options
python default_creds_scanner.py -t 192.168.1.0/24 -p 22,80,443,8080,23,21 -s ssh,http,telnet,ftp --timeout 3 --threads 15 -o scan_results.json -v
```

### Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-t, --target` | Target IP addresses, hostnames, or CIDR ranges | Required* |
| `-f, --file` | File containing list of targets (one per line) | Required* |
| `-p, --ports` | Comma-separated list of ports to scan | 22,80,443,23,21 |
| `-s, --services` | Comma-separated list of services to test | ssh,http,telnet,ftp |
| `--timeout` | Connection timeout in seconds | 3 |
| `--threads` | Number of concurrent threads | 5 |
| `-o, --output` | Output file for results | None |
| `--format` | Output format (json/txt) | json |
| `-v, --verbose` | Enable verbose output | False |

*Either `-t` or `-f` must be specified.

### Target File Format

Create a text file with one target per line:

```
# targets.txt
192.168.1.100
192.168.1.101
192.168.1.0/24
example.com
server.local
# Comments are supported
```

## Supported Services

### SSH (Port 22)
- Tests SSH authentication using paramiko library
- Supports key-based and password authentication detection
- Common default credentials for various SSH services

### HTTP (Ports 80, 443, 8080, etc.)
- Tests HTTP Basic Authentication
- Checks multiple common authentication paths
- Supports both HTTP and HTTPS
- Automatically handles SSL certificate verification

### Telnet (Port 23)
- Tests traditional telnet login
- Handles various login prompt formats
- Detects successful shell access

### FTP (Port 21)
- Tests FTP authentication
- Includes anonymous FTP detection
- Common FTP service default credentials

## Default Credentials Database

The tool includes an extensive database of default credentials for each service:

- **SSH**: admin/admin, root/root, pi/raspberry, ubuntu/ubuntu, etc.
- **HTTP**: admin/admin, admin/password, tomcat/tomcat, manager/manager, etc.
- **Telnet**: admin/admin, cisco/cisco, root/root, etc.
- **FTP**: admin/admin, ftp/ftp, anonymous/(blank), etc.

## Output Formats

### JSON Output
```json
{
  "scan_info": {
    "timestamp": "2024-01-15T10:30:00.123456",
    "total_findings": 2
  },
  "results": [
    {
      "host": "192.168.1.100",
      "port": 22,
      "service": "ssh",
      "username": "admin",
      "password": "admin",
      "timestamp": "2024-01-15T10:30:15.654321"
    }
  ]
}
```

### Text Output
```
Default Credentials Scan Results
Generated: 2024-01-15T10:30:00.123456
Total Findings: 1

Host: 192.168.1.100:22
Service: ssh
Credentials: admin:admin
Timestamp: 2024-01-15T10:30:15.654321
--------------------------------------------------
```

## Performance Considerations

- **Threading**: Adjust the `--threads` parameter based on your system capabilities and network conditions
- **Timeout**: Increase timeout for slow networks or decrease for faster scanning
- **Network load**: Be mindful of network bandwidth and target system load
- **Rate limiting**: Some systems may implement rate limiting or intrusion detection

## Security and Legal Considerations

### Legal Requirements
- **Authorization**: Only scan systems you own or have explicit written permission to test
- **Scope**: Ensure scanning activities are within the agreed scope of any security assessment
- **Documentation**: Maintain proper documentation of authorization and findings
- **Compliance**: Follow relevant industry standards and regulations (PCI DSS, SOX, etc.)

### Ethical Guidelines
- **Responsible disclosure**: Report vulnerabilities through proper channels
- **Minimal impact**: Configure timeouts and thread counts to minimize system impact
- **Data protection**: Handle any discovered credentials with appropriate security measures
- **Professional conduct**: Use findings to improve security, not for malicious purposes

### Detection Avoidance
- This tool generates significant network traffic and authentication attempts
- Most security monitoring systems will detect and alert on this activity
- Consider coordination with security teams during authorized testing

## Troubleshooting

### Common Issues

**Import Errors**
```bash
# Install missing dependencies
pip install paramiko requests
```

**Connection Timeouts**
```bash
# Increase timeout value
python default_creds_scanner.py -t 192.168.1.100 --timeout 10
```

**Too Many Threads**
```bash
# Reduce thread count for system stability
python default_creds_scanner.py -t 192.168.1.0/24 --threads 5
```

**Permission Errors**
```bash
# Ensure proper file permissions for output files
chmod 644 results.json
```

### Debug Mode

Enable verbose mode for detailed debugging information:

```bash
python default_creds_scanner.py -t 192.168.1.100 -v
```

## Contributing

Contributions are welcome! Please consider the following:

1. **Security focus**: Ensure all contributions maintain the security-focused nature of the tool
2. **Code quality**: Follow Python best practices and include proper documentation
3. **Testing**: Test new features thoroughly before submitting
4. **Credentials database**: When adding new default credentials, ensure they are from legitimate sources

### Adding New Services

To add support for new services:

1. Add service credentials to the `default_creds` dictionary
2. Implement a `test_[service]_credentials` method
3. Update the `scan_service` method to handle the new service
4. Add appropriate error handling and logging

## License

This project is licensed under the MIT License - see the LICENSE file for details.

```
MIT License

Copyright (c) 2024

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
- Initial release
- Support for SSH, HTTP, Telnet, and FTP services
- Multi-threaded scanning capability
- JSON and text output formats
- Comprehensive default credentials database
- CIDR range and target file support

## Support

For issues, questions, or contributions:

1. Check the troubleshooting section above
2. Review existing GitHub issues
3. Create a new issue with detailed information about your problem
4. Include system information, command used, and error messages

## Acknowledgments

- Thanks to the security community for sharing knowledge about default credentials
- Inspired by various penetration testing tools and methodologies
- Built with security professionals and ethical hackers in mind
- Special thanks to the developers of paramiko and requests libraries

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The developers assume no liability for any misuse or damage caused by this tool. Users are responsible for complying with all applicable laws and regulations.

Remember: **With great power comes great responsibility.** Use this tool ethically and responsibly.
