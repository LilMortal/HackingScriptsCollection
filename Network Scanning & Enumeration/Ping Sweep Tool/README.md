# Ping Sweep Tool

A powerful and efficient network discovery tool that performs ICMP ping sweeps to identify active hosts within specified IP ranges. This tool is designed for network administrators, security professionals, and anyone who needs to quickly discover live hosts on a network.

## Features

- **Multiple Input Formats**: Supports single IP addresses, CIDR notation, and IP ranges
- **Concurrent Scanning**: Multi-threaded scanning for improved performance
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Progress Tracking**: Real-time progress updates during scanning
- **Flexible Output**: Console output with optional file saving
- **Customizable Parameters**: Adjustable timeout and thread count
- **Input Validation**: Comprehensive error handling and input validation
- **Sorted Results**: Results are automatically sorted by IP address

## Installation

### Prerequisites

- Python 3.6 or higher
- Standard Python libraries (no external dependencies required)

### Download and Setup

1. Download the `ping_sweep.py` script
2. Make it executable (Linux/macOS):
   ```bash
   chmod +x ping_sweep.py
   ```

### No Additional Dependencies

This tool uses only Python standard libraries, so no additional packages need to be installed.

## Usage

### Basic Syntax

```bash
python ping_sweep.py [TARGET] [OPTIONS]
```

### Target Formats

1. **Single IP Address**:
   ```bash
   python ping_sweep.py 192.168.1.1
   ```

2. **CIDR Notation** (Subnet):
   ```bash
   python ping_sweep.py 192.168.1.0/24
   ```

3. **IP Range**:
   ```bash
   python ping_sweep.py 192.168.1.1-192.168.1.50
   ```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --timeout` | Timeout for each ping in seconds | 1.0 |
| `-j, --threads` | Maximum number of concurrent threads | 100 |
| `-o, --output` | Output file to save results | None |
| `-q, --quiet` | Suppress progress output | False |
| `--version` | Show version information | - |
| `-h, --help` | Show help message | - |

### Examples

#### Basic subnet scan:
```bash
python ping_sweep.py 192.168.1.0/24
```

#### Scan with custom timeout and thread count:
```bash
python ping_sweep.py 10.0.0.0/24 --timeout 2 --threads 50
```

#### Scan IP range and save results:
```bash
python ping_sweep.py 172.16.1.1-172.16.1.254 --output network_scan.txt
```

#### Quiet scan (no progress output):
```bash
python ping_sweep.py 192.168.0.0/24 --quiet
```

#### Large network scan with confirmation:
```bash
python ping_sweep.py 10.0.0.0/16 --timeout 0.5 --threads 200
```

## Sample Output

```
Starting ping sweep of 254 hosts...
Timeout: 1.0s | Max threads: 100
--------------------------------------------------
Progress: 100.0% (254/254) | Active hosts: 12

==================================================
SCAN COMPLETE
==================================================
Scan time: 3.45 seconds
Hosts scanned: 254
Active hosts: 12

Active Hosts:
--------------------
  192.168.1.1
  192.168.1.10
  192.168.1.15
  192.168.1.20
  192.168.1.25
  192.168.1.50
  192.168.1.100
  192.168.1.150
  192.168.1.200
  192.168.1.220
  192.168.1.230
  192.168.1.254
```

## Technical Details

### How It Works

1. **Input Parsing**: The tool parses various input formats (single IP, CIDR, range)
2. **IP Generation**: Creates a list of IP addresses to scan
3. **Concurrent Execution**: Uses ThreadPoolExecutor for parallel ping operations
4. **ICMP Ping**: Executes system ping command for each host
5. **Result Collection**: Collects and sorts active hosts
6. **Output**: Displays results and optionally saves to file

### Platform-Specific Behavior

- **Windows**: Uses `ping -n 1 -w [timeout_ms] [ip]`
- **Linux/Unix**: Uses `ping -c 1 -W [timeout_s] [ip]`
- **macOS**: Uses `ping -c 1 -W [timeout_s] [ip]`

### Performance Considerations

- **Thread Count**: Default of 100 threads provides good balance of speed and system resources
- **Timeout**: 1-second timeout is usually sufficient for local networks
- **Large Networks**: Tool will prompt for confirmation when scanning >65,536 hosts
- **Memory Usage**: Minimal memory footprint, scales well with network size

## Limitations

- **ICMP Filtering**: Some hosts may not respond to ICMP pings due to firewall rules
- **Requires Ping**: Relies on system ping command availability
- **Network Dependent**: Performance varies based on network conditions
- **No Authentication**: Does not handle networks requiring authentication
- **IPv4 Only**: Currently supports IPv4 addresses only

## Security and Ethical Considerations

⚠️ **Important Security Notes**:

- **Permission Required**: Only scan networks you own or have explicit permission to test
- **Legal Compliance**: Ensure compliance with local laws and organizational policies
- **Network Impact**: Large scans may impact network performance
- **Responsible Use**: Use responsibly and avoid scanning external networks without permission

### Best Practices

1. **Get Permission**: Always obtain proper authorization before scanning
2. **Limit Scope**: Scan only necessary IP ranges
3. **Consider Timing**: Perform scans during off-peak hours for large networks
4. **Monitor Impact**: Watch for any negative network performance impact
5. **Document**: Keep records of authorized scanning activities

## Troubleshooting

### Common Issues

1. **Permission Denied**:
   - On some systems, ping requires elevated privileges
   - Try running with `sudo` on Linux/macOS

2. **High False Negatives**:
   - Increase timeout value: `--timeout 2`
   - Some hosts may have ICMP disabled

3. **Slow Performance**:
   - Reduce thread count: `--threads 50`
   - Increase timeout for better accuracy: `--timeout 1.5`

4. **Large Network Warnings**:
   - Tool will prompt for confirmation on large scans
   - Consider breaking large ranges into smaller chunks

### Error Messages

- `Invalid IP address`: Check IP format and validity
- `Start IP must be less than or equal to end IP`: Verify IP range order
- `Timeout must be greater than 0`: Use positive timeout values
- `Thread count must be between 1 and 1000`: Adjust thread count

## Contributing

Contributions are welcome! Please feel free to submit pull requests or report issues.

### Development Setup

1. Clone or download the script
2. Make your changes
3. Test across different operating systems
4. Submit pull request with detailed description

## License

MIT License

Copyright (c) 2024 Network Tools

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

### Version 1.0
- Initial release
- Support for multiple input formats (single IP, CIDR, range)
- Multi-threaded scanning
- Cross-platform compatibility
- Progress tracking
- File output option
- Comprehensive error handling

## Support

For issues, questions, or feature requests, please create an issue in the project repository.

---

**Disclaimer**: This tool is for authorized network testing only. Users are responsible for ensuring they have proper permission to scan target networks and comply with all applicable laws and regulations.
