# Banner Grabber

A Python-based network service banner collection tool for network inventory, security assessment, and system administration.

## Description

Banner Grabber is a multi-threaded network scanning tool that connects to network services and retrieves their banners or service headers. This information can be used to identify service versions, configurations, and potential security issues. The tool supports various protocols including HTTP, SSH, FTP, SMTP, and more.

## Features

- Multi-threaded scanning for improved performance
- Support for multiple port specifications (single, comma-separated, ranges)
- Automatic service identification based on banners and ports
- Configurable timeouts and thread counts
- Output results to file
- Verbose logging options
- Built-in service probes for common protocols
- Clean, structured output format

## Installation

### Prerequisites

- Python 3.6 or higher
- No external dependencies (uses only standard library)

### Setup

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/your-repo/banner-grabber/main/banner_grabber.py
```

2. Make it executable (Linux/macOS):
```bash
chmod +x banner_grabber.py
```

3. Run the script:
```bash
python3 banner_grabber.py --help
```

## Usage

### Basic Syntax

```bash
python3 banner_grabber.py -t <target> -p <ports> [options]
```

### Required Arguments

- `-t, --target`: Target hostname or IP address
- `-p, --ports`: Port(s) to scan

### Optional Arguments

- `-T, --timeout`: Socket timeout in seconds (default: 3)
- `--threads`: Maximum number of concurrent threads (default: 10)
- `-o, --output`: Output file to save results
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Show help message

### Examples

#### Basic Usage

Scan a single port:
```bash
python3 banner_grabber.py -t example.com -p 80
```

Scan multiple specific ports:
```bash
python3 banner_grabber.py -t 192.168.1.1 -p 22,80,443
```

Scan a port range:
```bash
python3 banner_grabber.py -t example.com -p 1-100
```

#### Advanced Usage

Scan with custom timeout and thread count:
```bash
python3 banner_grabber.py -t example.com -p 1-1000 -T 5 --threads 20
```

Save results to file:
```bash
python3 banner_grabber.py -t example.com -p 80,443 --output results.txt
```

Enable verbose output:
```bash
python3 banner_grabber.py -t example.com -p 22,80,443 -v
```

### Port Specifications

The tool supports flexible port specification formats:

- **Single port**: `80`
- **Multiple ports**: `22,80,443`
- **Port range**: `1-1000`
- **Mixed**: `22,80,443,8000-8100`

### Output Format

The tool provides real-time output for open ports:

```
[OPEN] example.com:80 (http) - HTTP/1.1 200 OK Server: nginx/1.18.0...
[OPEN] example.com:443 (https) - HTTP/1.1 200 OK Server: nginx/1.18.0...
```

And a summary at the end:
```
Scan completed. Found 2 open ports out of 3 scanned.
```

## Service Detection

The tool automatically identifies services based on:

1. **Banner analysis**: Regex patterns matching common service banners
2. **Port-based identification**: Default services for well-known ports
3. **Protocol probes**: Service-specific requests for better banner collection

### Supported Services

- HTTP/HTTPS (ports 80, 443)
- SSH (port 22)
- FTP (port 21)
- SMTP (port 25)
- Telnet (port 23)
- POP3/POP3S (ports 110, 995)
- IMAP/IMAPS (ports 143, 993)
- DNS (port 53)

## Performance Considerations

- Default thread count is 10, which provides good performance for most use cases
- For large port ranges (>1000 ports), the tool will prompt for confirmation
- Timeout values between 3-10 seconds work well for most networks
- Higher thread counts may trigger rate limiting or appear as DoS attacks

## Ethical Use and Legal Considerations

⚠️ **Important Notice**: This tool is intended for legitimate network administration and security assessment purposes only.

### Authorized Use Only

- Only scan networks and systems you own or have explicit permission to test
- Obtain proper authorization before scanning any network
- Be aware of your organization's security policies
- Consider the potential impact on network performance

### Legal Compliance

- Banner grabbing may be considered reconnaissance activity
- Some jurisdictions have laws regarding network scanning
- Corporate networks often have policies against unauthorized scanning
- Always comply with applicable laws and regulations

### Responsible Disclosure

- If you discover vulnerabilities, follow responsible disclosure practices
- Contact system administrators or security teams appropriately
- Do not exploit or publicize vulnerabilities without permission

## Limitations

- IPv4 only (IPv6 support not implemented)
- TCP services only (no UDP support)
- Basic banner collection (no deep protocol analysis)
- May not work with services requiring authentication
- Some services may not respond to generic probes

## Troubleshooting

### Common Issues

**Connection timeouts**:
- Increase timeout value with `-T` flag
- Check network connectivity
- Verify target is reachable

**No banners received**:
- Some services don't send immediate banners
- Try increasing timeout
- Service may require specific authentication

**Permission denied**:
- Some systems restrict outbound connections
- Firewall rules may block scanning
- Consider running with appropriate privileges

**High CPU usage**:
- Reduce thread count with `--threads`
- Increase timeout to reduce retries
- Scan smaller port ranges

### Getting Help

If you encounter issues:

1. Run with `-v` flag for verbose output
2. Check network connectivity to target
3. Verify target hostname/IP is correct
4. Try with a single port first
5. Check firewall and security settings

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License

Copyright (c) 2024 Network Administrator

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

## Version History

- **v1.0.0**: Initial release
  - Multi-threaded banner grabbing
  - Service identification
  - Multiple output formats
  - Flexible port specification

## Acknowledgments

- Built using Python's standard library
- Inspired by traditional network reconnaissance tools
- Designed with security professionals and network administrators in mind
