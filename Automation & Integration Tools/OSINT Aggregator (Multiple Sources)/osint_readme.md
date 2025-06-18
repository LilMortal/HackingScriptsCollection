# OSINT Aggregator (Multiple Sources)

A comprehensive Python tool for aggregating Open Source Intelligence (OSINT) from multiple public sources. This tool is designed for legitimate cybersecurity research, digital forensics, and authorized penetration testing.

## ⚠️ Ethical Use Warning

**This tool is intended for legitimate research, cybersecurity analysis, and authorized penetration testing only.** Users are responsible for ensuring their use complies with all applicable laws and regulations. **Do not use this tool for unauthorized access, harassment, stalking, or any malicious activities.**

## Features

- **Multi-source OSINT gathering** from various public sources
- **Domain and IP address support** with automatic detection
- **Modular design** allowing selection of specific sources
- **Multiple output formats** (JSON, CSV)
- **Rate limiting** to respect target services
- **Comprehensive error handling** and logging
- **Shodan integration** (optional, requires API key)
- **Command-line interface** with extensive options

### Supported Sources

1. **WHOIS Information** - Domain registration details
2. **DNS Records** - A, AAAA, MX, NS, TXT, CNAME, SOA records
3. **HTTP Information** - Headers, server info, titles
4. **Subdomain Enumeration** - Common subdomain discovery
5. **Geolocation** - IP-based location information
6. **Shodan** - Security-focused search engine data (requires API key)

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Required Dependencies

Install the required packages using pip:

```bash
pip install requests dnspython python-whois
```

### Optional Dependencies

For Shodan integration:

```bash
pip install shodan
```

### Clone or Download

```bash
# Clone the repository (if using git)
git clone <repository-url>
cd osint-aggregator

# Or download the script directly
wget <script-url>/osint_aggregator.py
```

## Usage

### Basic Usage

```bash
# Basic domain investigation
python osint_aggregator.py --target example.com

# IP address investigation
python osint_aggregator.py --target 8.8.8.8

# Specify output file
python osint_aggregator.py --target example.com --output my_results.json
```

### Advanced Usage

```bash
# Use specific sources only
python osint_aggregator.py --target example.com --sources whois,dns,http

# Use all available sources
python osint_aggregator.py --target example.com --all-sources

# Export to CSV format
python osint_aggregator.py --target example.com --format csv --output results.csv

# Include Shodan data (requires API key)
python osint_aggregator.py --target example.com --shodan-key YOUR_API_KEY

# Verbose output for debugging
python osint_aggregator.py --target example.com --verbose
```

### Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--target` | `-t` | Target domain, IP address, or URL (required) |
| `--sources` | `-s` | Comma-separated list of sources to use |
| `--all-sources` | `-a` | Use all available sources |
| `--output` | `-o` | Output file path (default: osint_results.json) |
| `--format` | `-f` | Output format: json or csv (default: json) |
| `--shodan-key` | | Shodan API key for enhanced data |
| `--verbose` | `-v` | Enable verbose logging |
| `--help` | `-h` | Show help message |

### Available Sources

- `whois` - WHOIS registration information
- `dns` - DNS record enumeration
- `http` - HTTP/HTTPS server information
- `subdomains` - Common subdomain discovery
- `geolocation` - IP geolocation data
- `shodan` - Shodan search engine data (requires API key)

## Output Formats

### JSON Output (Default)

```json
{
  "target": "example.com",
  "timestamp": "2025-06-18T10:30:00",
  "sources": {
    "whois": {
      "registrar": "Example Registrar",
      "creation_date": "2000-01-01",
      "expiration_date": "2025-01-01"
    },
    "dns": {
      "A": ["93.184.216.34"],
      "MX": ["mail.example.com"]
    }
  }
}
```

### CSV Output

The CSV format flattens the hierarchical data structure:

```csv
Source,Key,Value
whois,registrar,Example Registrar
whois,creation_date,2000-01-01
dns,A,93.184.216.34
```

## Configuration

### Shodan API Key

To use Shodan integration:

1. Sign up for a free account at [shodan.io](https://shodan.io)
2. Get your API key from your account dashboard
3. Use the `--shodan-key` parameter or set it as an environment variable:

```bash
export SHODAN_API_KEY="your_api_key_here"
```

### Rate Limiting

The tool includes built-in rate limiting (1 second between requests) to be respectful to target services. This can be adjusted by modifying the `request_delay` parameter in the code.

## Examples

### Example 1: Basic Domain Investigation

```bash
python osint_aggregator.py --target google.com --output google_osint.json
```

### Example 2: Comprehensive Analysis

```bash
python osint_aggregator.py --target target-domain.com --all-sources --shodan-key YOUR_KEY --verbose
```

### Example 3: IP Address Investigation

```bash
python osint_aggregator.py --target 1.1.1.1 --sources dns,geolocation,shodan --shodan-key YOUR_KEY
```

### Example 4: CSV Export for Spreadsheet Analysis

```bash
python osint_aggregator.py --target example.com --format csv --output analysis.csv
```

## Troubleshooting

### Common Issues

1. **DNS Resolution Errors**: Ensure you have internet connectivity and the target is valid
2. **Rate Limiting**: If you encounter rate limits, the tool will automatically retry with delays
3. **Missing Dependencies**: Install all required packages using pip
4. **Shodan API Errors**: Verify your API key is valid and has sufficient credits

### Error Codes

- Exit code 0: Success
- Exit code 1: General error or user cancellation

### Logging

Use the `--verbose` flag to enable detailed logging for debugging purposes.

## Legal and Ethical Considerations

### Legitimate Use Cases

- **Cybersecurity Research**: Analyzing your own infrastructure
- **Digital Forensics**: Authorized investigations
- **Penetration Testing**: With proper authorization
- **Academic Research**: Educational purposes
- **Threat Intelligence**: Analyzing known malicious infrastructure

### Prohibited Uses

- Unauthorized access or reconnaissance
- Harassment or stalking
- Violating terms of service of target websites
- Any illegal activities

### Compliance

Users must ensure compliance with:
- Local and international laws
- Terms of service of data sources
- Ethical hacking guidelines
- Corporate security policies

## Limitations

- **Rate Limiting**: Queries are rate-limited to be respectful to services
- **Public Data Only**: Only collects publicly available information
- **API Limitations**: Some sources may require API keys or have usage limits
- **Accuracy**: Information accuracy depends on source data quality
- **Coverage**: Not all subdomains or services may be discovered

## Contributing

Contributions are welcome! Please ensure any modifications maintain the ethical use focus and include proper error handling.

### Development Guidelines

1. Follow PEP 8 style guidelines
2. Include comprehensive error handling
3. Add logging for debugging
4. Update documentation for new features
5. Test with various target types

## Dependencies

### Required

- `requests` - HTTP library for web requests
- `dnspython` - DNS toolkit for Python
- `python-whois` - WHOIS lookup functionality

### Optional

- `shodan` - Shodan search engine integration

## License

MIT License

Copyright (c) 2025 OSINT Aggregator

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

This tool is provided for educational and legitimate security research purposes only. The authors are not responsible for any misuse or damage caused by this tool. Users are solely responsible for ensuring their use complies with all applicable laws and regulations.

## Support

For issues, questions, or contributions:

1. Check the troubleshooting section
2. Review the command-line help: `python osint_aggregator.py --help`
3. Enable verbose logging for debugging: `--verbose`

## Version History

- **v1.0.0**: Initial release with multi-source OSINT aggregation
  - WHOIS, DNS, HTTP, subdomain, and geolocation support
  - JSON and CSV export formats
  - Command-line interface
  - Shodan integration
  - Comprehensive error handling and logging