# WHOIS Lookup Script

A comprehensive command-line tool for performing WHOIS lookups on domain names. This script provides detailed domain registration information including registrar details, creation/expiration dates, name servers, and contact information.

## Features

- **Multi-TLD Support**: Supports 30+ top-level domains including .com, .org, .net, .uk, .de, .io, and many more
- **Flexible Output**: Display results in human-readable text or JSON format
- **File Export**: Save lookup results to a file
- **Error Handling**: Robust error handling with informative messages
- **Timeout Control**: Configurable connection timeout
- **Referral Following**: Automatically follows WHOIS server referrals for complete information
- **Input Validation**: Validates domain name format before performing lookups

## Installation

### Prerequisites

- Python 3.6 or higher
- No external dependencies required (uses only Python standard library)

### Setup

1. Download the script:
   ```bash
   wget https://raw.githubusercontent.com/yourusername/whois-lookup/main/whois_lookup.py
   # or
   curl -O https://raw.githubusercontent.com/yourusername/whois-lookup/main/whois_lookup.py
   ```

2. Make the script executable (Linux/macOS):
   ```bash
   chmod +x whois_lookup.py
   ```

3. Optionally, move to a directory in your PATH:
   ```bash
   sudo mv whois_lookup.py /usr/local/bin/whois-lookup
   ```

## Usage

### Basic Usage

```bash
# Simple domain lookup
python whois_lookup.py example.com

# Using the --domain flag
python whois_lookup.py --domain example.com
```

### Advanced Usage

```bash
# Output in JSON format
python whois_lookup.py --domain google.com --output json

# Save results to a file
python whois_lookup.py --domain github.com --save results.txt

# JSON output saved to file
python whois_lookup.py --domain stackoverflow.com --output json --save data.json

# Custom timeout (30 seconds)
python whois_lookup.py --domain example.com --timeout 30
```

### Command-Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--domain` | `-d` | Domain name to lookup | Required |
| `--output` | `-o` | Output format (text/json) | text |
| `--save` | `-s` | Save output to file | None |
| `--timeout` | `-t` | Connection timeout in seconds | 10 |
| `--version` | | Show version information | |
| `--help` | `-h` | Show help message | |

## Output Information

The script extracts and displays the following information when available:

- **Domain Name**: The queried domain
- **Registrar**: Domain registrar company
- **Creation Date**: When the domain was first registered
- **Expiration Date**: When the domain registration expires
- **Updated Date**: Last modification date
- **Status**: Current domain status (active, expired, etc.)
- **Name Servers**: DNS servers for the domain
- **Registrant**: Domain owner information
- **Administrative Contact**: Admin contact details
- **Technical Contact**: Technical contact details

## Supported TLDs

The script includes built-in support for the following top-level domains:

- **Generic TLDs**: .com, .net, .org, .info, .biz, .io, .co, .me, .tv, .cc, .ly
- **Country TLDs**: .us, .uk, .de, .fr, .jp, .au, .ca, .br, .ru, .cn, .in, .mx, .nl, .be, .it, .es, .ch, .se, .no

For unsupported TLDs, the script will attempt to use the IANA WHOIS server as a fallback.

## Examples

### Example 1: Basic Text Output
```bash
$ python whois_lookup.py example.com

Looking up WHOIS information for: example.com
Please wait...

Lookup completed in 1.23 seconds

==================================================
WHOIS LOOKUP RESULTS
==================================================
Domain: EXAMPLE.COM
Registrar: RESERVED-Internet Assigned Numbers Authority
Created: 1995-08-14T04:00:00Z
Expires: 2024-08-13T04:00:00Z
Updated: 2023-08-14T07:01:31Z
Status: clientDeleteProhibited, clientTransferProhibited, clientUpdateProhibited
Name Servers:
  - A.IANA-SERVERS.NET
  - B.IANA-SERVERS.NET
==================================================
```

### Example 2: JSON Output
```bash
$ python whois_lookup.py --domain example.com --output json

{
  "domain": "EXAMPLE.COM",
  "registrar": "RESERVED-Internet Assigned Numbers Authority",
  "creation_date": "1995-08-14T04:00:00Z",
  "expiration_date": "2024-08-13T04:00:00Z",
  "updated_date": "2023-08-14T07:01:31Z",
  "status": [
    "clientDeleteProhibited",
    "clientTransferProhibited",
    "clientUpdateProhibited"
  ],
  "name_servers": [
    "A.IANA-SERVERS.NET",
    "B.IANA-SERVERS.NET"
  ],
  "registrant": "",
  "admin_contact": "",
  "tech_contact": ""
}
```

## Error Handling

The script includes comprehensive error handling for common issues:

- **Invalid Domain Format**: Validates domain names before lookup
- **Network Errors**: Handles connection timeouts and server unavailability
- **DNS Resolution**: Manages cases where WHOIS servers are unreachable
- **File I/O Errors**: Graceful handling of file save operations

## Limitations

- **Rate Limiting**: Some WHOIS servers implement rate limiting. If you encounter errors, wait a few minutes before retrying
- **Server Variations**: WHOIS data format varies between servers; some fields may not be available for all domains
- **Privacy Protection**: Domains with privacy protection may return limited information
- **Regional Restrictions**: Some ccTLD WHOIS servers may have access restrictions

## Ethical Use Guidelines

This tool is intended for legitimate purposes such as:
- Domain research and due diligence
- Network administration
- Security research
- Academic purposes

**Please use responsibly:**
- Don't perform bulk lookups that could overload WHOIS servers
- Respect rate limits and terms of service
- Don't use for spam or malicious purposes
- Consider the privacy implications of WHOIS data

## Troubleshooting

### Common Issues

1. **Connection Timeout**
   ```
   Solution: Increase timeout with --timeout 30
   ```

2. **Domain Not Found**
   ```
   Solution: Verify domain spelling and TLD
   ```

3. **Permission Denied (File Save)**
   ```
   Solution: Check file permissions and disk space
   ```

4. **Invalid Domain Format**
   ```
   Solution: Ensure domain follows standard format (e.g., example.com)
   ```

## Contributing

Contributions are welcome! Here are ways you can help:

1. **Report Bugs**: Create detailed issue reports
2. **Add TLD Support**: Contribute WHOIS servers for additional TLDs
3. **Improve Parsing**: Enhance data extraction for different server formats
4. **Documentation**: Improve documentation and examples

## License

MIT License

Copyright (c) 2024 [Your Name]

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

### v1.0.0 (2024-06-18)
- Initial release
- Support for 30+ TLDs
- Text and JSON output formats
- File export functionality
- Comprehensive error handling
- Command-line interface with argparse

## Support

For questions, bug reports, or feature requests, please:
1. Check the troubleshooting section above
2. Search existing issues on GitHub
3. Create a new issue with detailed information

---

**Disclaimer**: This tool queries public WHOIS databases. The availability and accuracy of information depends on the respective WHOIS servers and domain registrars. Always verify critical information through official channels.
