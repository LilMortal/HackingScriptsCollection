# Traceroute Script

A Python implementation of the traceroute network diagnostic tool. This script traces the route packets take from your computer to a destination host, showing each hop along the way with timing information.

## Description

This traceroute implementation sends packets with incrementally increasing Time-To-Live (TTL) values to discover the path packets take through the network to reach a destination. Each router along the path decrements the TTL and, when it reaches zero, sends back an ICMP "Time Exceeded" message, revealing the router's IP address.

## Features

- **Cross-platform compatibility**: Works on Linux, macOS, and Windows
- **Flexible probe options**: Configurable number of probes per hop
- **Hostname resolution**: Automatically resolves IP addresses to hostnames
- **Timeout control**: Adjustable timeout for each probe
- **Error handling**: Comprehensive error handling and user-friendly messages
- **Privilege handling**: Gracefully handles running without root privileges
- **Command-line interface**: Full argument parsing with help and examples

## Installation

### Prerequisites

- Python 3.6 or higher
- For full ICMP functionality: root/administrator privileges

### Dependencies

This script uses only Python standard library modules:
- `socket` - For network operations
- `struct` - For packet manipulation
- `time` - For timing measurements
- `argparse` - For command-line argument parsing
- `sys` and `os` - For system operations

No external dependencies need to be installed.

### Setup

1. Download the script:
   ```bash
   wget https://raw.githubusercontent.com/your-repo/traceroute.py
   # or
   curl -O https://raw.githubusercontent.com/your-repo/traceroute.py
   ```

2. Make it executable:
   ```bash
   chmod +x traceroute.py
   ```

3. Optionally, move to a directory in your PATH:
   ```bash
   sudo mv traceroute.py /usr/local/bin/traceroute.py
   ```

## Usage

### Basic Usage

```bash
# Basic traceroute to a hostname
python traceroute.py google.com

# Basic traceroute to an IP address
python traceroute.py 8.8.8.8
```

### Advanced Usage

```bash
# Limit maximum hops and set timeout
python traceroute.py -m 20 -t 2 example.com

# Disable hostname resolution for faster execution
python traceroute.py --no-resolve 8.8.8.8

# Use more probes per hop for better accuracy
python traceroute.py -p 5 google.com

# Run with root privileges for ICMP support (recommended)
sudo python traceroute.py google.com
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `destination` | Target hostname or IP address | Required |
| `-m, --max-hops` | Maximum number of hops to trace | 30 |
| `-t, --timeout` | Timeout for each probe (seconds) | 5.0 |
| `-p, --probes` | Number of probes per hop | 3 |
| `--no-resolve` | Don't resolve IP addresses to hostnames | False |
| `--version` | Show version information | - |
| `-h, --help` | Show help message | - |

### Examples

```bash
# Trace route to Google with custom settings
python traceroute.py -m 15 -t 3 -p 4 google.com

# Quick trace without hostname resolution
python traceroute.py --no-resolve -t 1 8.8.8.8

# Trace to local network device
python traceroute.py 192.168.1.1

# Get help
python traceroute.py --help
```

## Understanding the Output

```
traceroute to google.com (172.217.16.142), 30 hops max
 1  192.168.1.1  1.234 ms  1.156 ms  1.098 ms
 2  10.0.0.1  15.678 ms  14.567 ms  16.789 ms
 3  * * *
 4  example-router.isp.com (203.0.113.1)  25.123 ms  24.987 ms  25.456 ms
```

- **Hop number**: The position in the route (1, 2, 3, etc.)
- **Hostname (IP)**: The router's hostname and IP address
- **Response times**: Three probe measurements in milliseconds
- **Asterisks (*)**: Indicate timeouts or blocked responses

## Privileges and Permissions

### ICMP Mode (Recommended)
- **Requires**: Root/administrator privileges
- **Advantages**: More accurate, follows standard traceroute behavior
- **Usage**: `sudo python traceroute.py destination`

### UDP Mode (Fallback)
- **Requires**: No special privileges
- **Limitations**: Cannot receive ICMP responses, shows only timeouts
- **Usage**: `python traceroute.py destination`

### Platform-Specific Notes

#### Linux
```bash
# Run with sudo for ICMP support
sudo python traceroute.py google.com

# Or grant capabilities to Python (advanced)
sudo setcap cap_net_raw+ep /usr/bin/python3
```

#### macOS
```bash
# Run with sudo
sudo python traceroute.py google.com
```

#### Windows
```cmd
# Run Command Prompt as Administrator
python traceroute.py google.com
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```
   Error: Permission denied: ICMP sockets require root privileges
   ```
   **Solution**: Run with `sudo` or administrator privileges

2. **Hostname Resolution Failed**
   ```
   Error: Cannot resolve hostname 'invalid-host'
   ```
   **Solution**: Check the hostname spelling or use an IP address

3. **Network Unreachable**
   ```
   Error: Network is unreachable
   ```
   **Solution**: Check your network connection and firewall settings

4. **Timeouts**
   ```
   * * *
   ```
   **Solution**: Some routers don't respond to traceroute probes, this is normal

### Performance Tips

- Use `--no-resolve` for faster execution
- Reduce timeout with `-t` for quicker results
- Increase probes with `-p` for more accurate measurements

## Limitations

- **Firewall blocking**: Some firewalls block ICMP or traceroute traffic
- **Load balancing**: Results may vary due to network load balancing
- **IPv6**: This implementation supports IPv4 only
- **Accuracy**: Network conditions can affect timing measurements

## Ethical Usage and Legal Considerations

### Responsible Use
- Only trace routes to hosts you own or have permission to test
- Respect network policies and terms of service
- Don't use for network scanning or reconnaissance without authorization
- Be mindful of network load when using frequent probes

### Educational Purpose
This tool is intended for:
- Network troubleshooting and diagnostics
- Learning about network routing and protocols
- System administration tasks
- Educational exploration of network paths

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- Feature enhancements
- Documentation improvements
- Cross-platform compatibility issues

## License

MIT License

Copyright (c) 2024 Traceroute Script

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

### v1.0 (Initial Release)
- Basic traceroute functionality
- ICMP and UDP probe support
- Hostname resolution
- Command-line argument parsing
- Comprehensive error handling
- Cross-platform compatibility

## Support

For issues, questions, or contributions:
- Open an issue on the project repository
- Check the troubleshooting section above
- Review the examples and documentation

---

**Note**: This is an educational implementation. For production network diagnostics, consider using system-provided traceroute tools (`traceroute` on Unix/Linux, `tracert` on Windows) which may have additional optimizations and features.
