# Network Protocol Analysis Tool

A comprehensive Python-based network packet analyzer that captures and analyzes network traffic to provide insights into protocol usage, traffic patterns, and network behavior. This tool is designed for educational purposes, network troubleshooting, and security analysis.

## Features

- **Live Packet Capture**: Capture packets from any network interface
- **Protocol Analysis**: Analyze various network protocols (TCP, UDP, ICMP, ARP, etc.)
- **Traffic Statistics**: Generate detailed statistics about network traffic
- **Flexible Filtering**: Use BPF (Berkeley Packet Filter) syntax for precise packet filtering
- **Data Export**: Save analysis results in JSON format
- **Visualization**: Create charts and graphs of network traffic patterns
- **Real-time Monitoring**: Display capture progress and statistics

## Requirements

- Python 3.6 or higher
- Administrator/root privileges (required for packet capture)
- Network interface access

## Installation

### 1. Clone or Download the Script

Save the `network_protocol_analyzer.py` script to your desired directory.

### 2. Install Required Dependencies

```bash
# Install required packages
pip install scapy

# Optional: Install additional packages for enhanced features
pip install matplotlib netifaces
```

### 3. Platform-Specific Setup

#### Windows
- Install [Npcap](https://nmap.org/npcap/) or WinPcap
- Run Command Prompt as Administrator

#### Linux
```bash
# Install additional dependencies
sudo apt-get update
sudo apt-get install python3-pip python3-dev libpcap-dev

# Run with sudo for packet capture
sudo python3 network_protocol_analyzer.py
```

#### macOS
```bash
# Install dependencies
brew install libpcap
pip install scapy

# Run with sudo for packet capture
sudo python3 network_protocol_analyzer.py
```

## Usage

### Basic Usage

```bash
# Capture 100 packets from any interface
python network_protocol_analyzer.py

# Capture from specific interface
python network_protocol_analyzer.py -i eth0 -c 50

# Use packet filtering
python network_protocol_analyzer.py -f "tcp port 80" -c 100
```

### Advanced Usage

```bash
# Capture with output file and visualization
python network_protocol_analyzer.py -i wlan0 -c 200 -o analysis.json --visualize

# Capture HTTP traffic only
python network_protocol_analyzer.py -f "tcp port 80 or tcp port 443" -c 100

# Capture from specific host
python network_protocol_analyzer.py -f "host 192.168.1.1" -c 50

# Verbose output
python network_protocol_analyzer.py -v -c 100
```

### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--interface` | `-i` | Network interface to capture from | `any` |
| `--count` | `-c` | Number of packets to capture | `100` |
| `--filter` | `-f` | BPF filter string | None |
| `--output` | `-o` | Output file for results (JSON) | None |
| `--visualize` | | Create visualization charts | False |
| `--output-dir` | | Directory for output files | Current directory |
| `--verbose` | `-v` | Enable verbose logging | False |

### BPF Filter Examples

```bash
# Capture only TCP traffic
-f "tcp"

# Capture traffic on specific port
-f "port 80"

# Capture traffic from/to specific IP
-f "host 192.168.1.100"

# Capture HTTP and HTTPS traffic
-f "tcp port 80 or tcp port 443"

# Capture traffic from specific subnet
-f "net 192.168.1.0/24"

# Capture UDP DNS traffic
-f "udp port 53"
```

## Output

The tool provides several types of output:

### 1. Console Report
Real-time analysis report displayed in the terminal with:
- Capture information
- Basic statistics (packet count, bytes, rates)
- Protocol distribution
- Top IP addresses and ports
- Packet size statistics

### 2. JSON Export
Detailed analysis results saved in JSON format containing:
- Raw statistics
- Protocol breakdowns
- Traffic patterns
- Timing information

### 3. Visualizations (Optional)
Generated charts include:
- Protocol distribution pie chart
- Packet size distribution histogram

## Example Output

```
================================================================================
NETWORK PROTOCOL ANALYSIS REPORT
================================================================================

Capture Information:
  Interface: eth0
  Filter: tcp port 80
  Capture Time: 2025-06-21T10:30:00
  Duration: 30.45 seconds

Basic Statistics:
  Total Packets: 150
  Total Bytes: 98,543
  Average Packet Size: 656.95 bytes
  Packets per Second: 4.93

Protocol Distribution:
  TCP: 120 packets (80.0%)
  IPv4: 150 packets (100.0%)
  Ethernet: 150 packets (100.0%)

Top IP Addresses:
  192.168.1.100: 45 packets
  10.0.0.1: 32 packets
  172.16.0.5: 28 packets

Top Ports:
  Port 80: 89 packets
  Port 443: 31 packets
  Port 53: 15 packets
```

## Ethical Use and Legal Considerations

⚠️ **Important Notice**: This tool is intended for educational and legitimate network analysis purposes only.

### Acceptable Use
- Analyzing your own network traffic
- Educational purposes and learning
- Network troubleshooting and optimization
- Security research on authorized networks
- Compliance monitoring on corporate networks

### Prohibited Use
- Capturing traffic on networks without proper authorization
- Intercepting communications without consent
- Any malicious or illegal activities
- Violating privacy rights or data protection laws

### Legal Compliance
- Ensure you have proper authorization before capturing network traffic
- Comply with local laws and regulations regarding network monitoring
- Respect privacy rights and data protection requirements
- Use only on networks you own or have explicit permission to monitor

## Limitations

- Requires administrative privileges for packet capture
- Performance may vary based on network traffic volume
- Some advanced protocols may not be fully analyzed
- Encrypted traffic content cannot be inspected (only metadata)
- May not capture all packets on high-traffic networks

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Solution: Run with administrator/root privileges
   - Windows: Run Command Prompt as Administrator
   - Linux/macOS: Use `sudo`

2. **Interface Not Found**
   - Solution: Use `--interface any` or check available interfaces
   - Linux: Use `ip link show` to list interfaces
   - Windows: Check network adapter names

3. **No Packets Captured**
   - Check if the interface is active and has traffic
   - Verify BPF filter syntax
   - Ensure network interface is up

4. **Scapy Import Error**
   - Solution: Install scapy with `pip install scapy`
   - May require additional system dependencies

### Getting Help

If you encounter issues:
1. Run with `-v` flag for verbose output
2. Check that all dependencies are installed
3. Verify you have the necessary permissions
4. Ensure the network interface is active

## License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2025 Network Protocol Analyzer

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

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## Disclaimer

This tool is provided for educational and legitimate network analysis purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors are not responsible for any misuse of this tool.
