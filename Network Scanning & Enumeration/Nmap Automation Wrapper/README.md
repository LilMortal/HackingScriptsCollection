# Nmap Automation Wrapper

A Python wrapper script for automating Nmap network scans with predefined scan types, output formatting, and result processing capabilities. This tool simplifies common network scanning tasks while maintaining flexibility for advanced users.

## Description

The Nmap Automation Wrapper provides a user-friendly interface to Nmap with predefined scan configurations for common use cases. It includes input validation, error handling, and multiple output formats to streamline network discovery and security auditing tasks.

### Key Features

- **Predefined Scan Types**: Quick, comprehensive, stealth, port-scan, UDP scan, version detection, OS detection, and vulnerability scanning
- **Multiple Output Formats**: XML, JSON, plain text, and grepable formats
- **Input Validation**: Validates IP addresses, networks, hostnames, and port ranges
- **Error Handling**: Comprehensive error handling with meaningful error messages
- **Result Processing**: Parse and convert XML results to JSON format
- **Command-line Interface**: Easy-to-use CLI with helpful examples

## Prerequisites

- Python 3.6 or higher
- Nmap installed and accessible from command line

## Installation

### 1. Install Nmap

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install nmap  # or dnf install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Download and install from [https://nmap.org/download.html](https://nmap.org/download.html)

### 2. Download the Script

Save the `nmap_wrapper.py` script to your desired location and make it executable:

```bash
chmod +x nmap_wrapper.py
```

### 3. Verify Installation

```bash
python3 nmap_wrapper.py --version
nmap --version
```

## Usage

### Basic Syntax

```bash
python3 nmap_wrapper.py -t TARGET -s SCAN_TYPE [OPTIONS]
```

### Command-line Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `-t, --target` | Target IP, hostname, or network | Yes |
| `-s, --scan-type` | Type of scan to perform | Yes |
| `-p, --ports` | Specific ports to scan | No |
| `-o, --output` | Output file path | No |
| `-f, --format` | Output format (xml, json, txt, grepable) | No |
| `-a, --additional-args` | Additional Nmap arguments | No |
| `-v, --verbose` | Enable verbose output | No |
| `--version` | Show version information | No |

### Scan Types

| Scan Type | Description | Nmap Flags |
|-----------|-------------|------------|
| `quick` | Fast scan of most common ports | `-T4 -F` |
| `comprehensive` | Complete scan with version/OS detection | `-sS -sV -O -A -T4` |
| `stealth` | Slow, stealthy scan | `-sS -T2` |
| `port-scan` | Standard TCP port scan | `-sS -T4` |
| `udp-scan` | UDP port scan | `-sU -T4` |
| `version-detect` | Service version detection | `-sV -T4` |
| `os-detect` | Operating system detection | `-O -T4` |
| `vuln-scan` | Vulnerability scanning with scripts | `-sV --script vuln -T4` |

### Examples

#### Basic Scans

```bash
# Quick scan of a single host
python3 nmap_wrapper.py -t 192.168.1.1 -s quick

# Comprehensive scan of a network
python3 nmap_wrapper.py -t 192.168.1.0/24 -s comprehensive

# Stealth scan of a hostname
python3 nmap_wrapper.py -t example.com -s stealth
```

#### Scans with Specific Ports

```bash
# Scan specific ports
python3 nmap_wrapper.py -t 192.168.1.1 -s port-scan -p 80,443,22

# Scan port range
python3 nmap_wrapper.py -t 192.168.1.1 -s port-scan -p 1-1000
```

#### Output to Files

```bash
# Save results as XML
python3 nmap_wrapper.py -t 192.168.1.0/24 -s quick -o results.xml

# Save results as JSON
python3 nmap_wrapper.py -t 192.168.1.1 -s comprehensive -o results.json -f json

# Save results as plain text
python3 nmap_wrapper.py -t example.com -s version-detect -o results.txt -f txt
```

#### Advanced Usage

```bash
# Verbose output with additional Nmap arguments
python3 nmap_wrapper.py -t 192.168.1.1 -s comprehensive -a "--reason --traceroute" -v

# Vulnerability scan with custom output
python3 nmap_wrapper.py -t target.com -s vuln-scan -o vuln_results.json -f json -v
```

#### Target Formats

The script accepts various target formats:

```bash
# Single IP address
python3 nmap_wrapper.py -t 192.168.1.1 -s quick

# IP range
python3 nmap_wrapper.py -t 192.168.1.1-10 -s quick

# Network with CIDR notation
python3 nmap_wrapper.py -t 192.168.1.0/24 -s quick

# Hostname
python3 nmap_wrapper.py -t example.com -s quick

# Multiple targets (space-separated in quotes)
python3 nmap_wrapper.py -t "192.168.1.1 192.168.1.5" -s quick
```

## Output Formats

### XML Format
Standard Nmap XML output that can be imported into other security tools.

### JSON Format
Parsed and structured JSON format for easy programmatic processing.

### Plain Text Format
Human-readable text output.

### Grepable Format
Single-line format suitable for grep and other text processing tools.

## Error Handling

The script includes comprehensive error handling for:

- Invalid target formats
- Missing Nmap installation
- Network connectivity issues
- Permission errors
- Scan timeouts (1-hour limit)
- Invalid port specifications

## Security Considerations

### ⚠️ Important Security and Legal Notes

1. **Authorization Required**: Only scan networks and systems you own or have explicit written permission to test
2. **Legal Compliance**: Ensure compliance with local laws and regulations
3. **Responsible Disclosure**: If vulnerabilities are found, follow responsible disclosure practices
4. **Network Impact**: Some scans may be detected by intrusion detection systems
5. **Resource Usage**: Comprehensive scans can consume significant bandwidth and time

### Ethical Use Guidelines

- Always obtain proper authorization before scanning
- Use stealth scans in production environments to minimize impact
- Respect rate limits and avoid overwhelming target systems
- Document and secure scan results appropriately
- Follow your organization's security testing policies

## Limitations

- Requires Nmap to be installed and accessible
- Scan timeout is set to 1 hour maximum
- Some advanced Nmap features may require additional configuration
- UDP scans may require elevated privileges on some systems
- Performance depends on network conditions and target responsiveness

## Troubleshooting

### Common Issues

**"Nmap is not installed or not accessible"**
- Ensure Nmap is installed and in your system PATH
- Try running `nmap --version` to verify installation

**"Invalid target"**
- Check target format (IP, hostname, or network)
- Ensure network notation is correct (e.g., 192.168.1.0/24)

**Permission denied errors**
- Some scan types require elevated privileges
- Try running with `sudo` on Unix-like systems
- Ensure you have permission to scan the target

**Scan timeouts**
- Reduce scan scope or use faster scan types
- Check network connectivity to target
- Consider using stealth mode for slower, more reliable scans

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Submit a pull request with a clear description

## Version History

- **1.0.0** - Initial release with core functionality

## License

MIT License

Copyright (c) 2025 Network Security Tools

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

This tool is intended for legitimate network security testing and administration purposes only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems. The authors assume no liability for misuse of this tool.

## Support

For bug reports, feature requests, or questions:
- Check the troubleshooting section above
- Review existing issues in the project repository
- Create a new issue with detailed information about your problem

## Acknowledgments

- The Nmap Project for creating the powerful network scanning tool
- The Python community for excellent libraries and documentation
- Security professionals who provide feedback and suggestions for improvement
