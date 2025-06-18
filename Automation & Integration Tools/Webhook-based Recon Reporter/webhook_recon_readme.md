# Webhook-based Recon Reporter

A comprehensive Python script for performing network reconnaissance and security assessments, with automated reporting via webhooks. This tool is designed for security professionals, penetration testers, and system administrators who need to perform reconnaissance tasks and receive automated reports.

## Features

- **Multi-target reconnaissance**: Scan single targets or batch process from files
- **Comprehensive scanning**: DNS lookups, port scanning, HTTP reconnaissance, and WHOIS queries
- **Flexible scan types**: Choose from basic, full, port-only, or web-only scans
- **Webhook integration**: Automatic reporting to Discord, Slack, or custom webhook endpoints
- **Concurrent processing**: Multi-threaded port scanning for improved performance
- **Detailed reporting**: JSON output with comprehensive scan results
- **Error handling**: Robust error handling and input validation
- **Command-line interface**: Easy-to-use CLI with comprehensive options

## Installation

### Prerequisites

- Python 3.6 or higher
- Network connectivity for webhook reporting

### Required Dependencies

```bash
pip install requests
```

### Optional Dependencies

For advanced port scanning capabilities:
```bash
pip install python-nmap
```

Note: The `whois` system command should be available for WHOIS lookups (pre-installed on most Linux/macOS systems).

### Installation Steps

1. Clone or download the script:
```bash
curl -O https://raw.githubusercontent.com/your-repo/webhook_recon_reporter.py
```

2. Make the script executable:
```bash
chmod +x webhook_recon_reporter.py
```

3. Install dependencies:
```bash
pip install requests
```

## Usage

### Basic Usage

Scan a single target and send results to a Discord webhook:
```bash
python webhook_recon_reporter.py --target example.com --webhook-url https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN
```

### Advanced Usage Examples

**Batch scanning from file:**
```bash
python webhook_recon_reporter.py --target-file targets.txt --webhook-url https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK --scan-type full
```

**Basic scan with JSON output:**
```bash
python webhook_recon_reporter.py --target 192.168.1.1 --webhook-url https://your-webhook.com/endpoint --scan-type basic --output results.json
```

**Port-only scan with custom timeout:**
```bash
python webhook_recon_reporter.py --target example.com --webhook-url https://discord.com/api/webhooks/xxx --scan-type port-only --timeout 5
```

**Web reconnaissance only:**
```bash
python webhook_recon_reporter.py --target example.com --webhook-url https://your-webhook.com --scan-type web-only
```

**Test mode (no webhook sending):**
```bash
python webhook_recon_reporter.py --target example.com --webhook-url https://example.com --no-webhook --output test_results.json
```

### Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--target` | `-t` | Single target hostname or IP address |
| `--target-file` | `-f` | File containing list of targets (one per line) |
| `--webhook-url` | `-w` | **Required** Webhook URL for sending reports |
| `--scan-type` | `-s` | Scan type: `basic`, `full`, `port-only`, `web-only` (default: `full`) |
| `--output` | `-o` | Output file path for detailed JSON results |
| `--timeout` | | Network operation timeout in seconds (default: 10) |
| `--no-webhook` | | Skip webhook reporting (useful for testing) |
| `--version` | | Show version information |
| `--help` | `-h` | Show help message |

### Scan Types

- **`full`**: Complete reconnaissance including DNS, port scan, HTTP, and WHOIS
- **`basic`**: DNS lookup, port scan, and HTTP reconnaissance
- **`port-only`**: DNS lookup and port scanning only
- **`web-only`**: DNS lookup and HTTP reconnaissance only

### Target File Format

Create a text file with one target per line:
```
example.com
192.168.1.1
subdomain.example.org
# This is a comment and will be ignored
another-target.com
```

## Webhook Integration

### Supported Platforms

- **Discord**: Use Discord webhook URLs
- **Slack**: Use Slack incoming webhook URLs
- **Custom webhooks**: Any endpoint accepting JSON POST requests

### Discord Webhook Setup

1. Go to your Discord server settings
2. Navigate to Integrations → Webhooks
3. Create a new webhook
4. Copy the webhook URL

### Slack Webhook Setup

1. Go to your Slack workspace
2. Navigate to Apps → Incoming Webhooks
3. Add to Slack and configure
4. Copy the webhook URL

### Custom Webhook Format

The script sends JSON payloads in this format:
```json
{
  "content": "Formatted text report",
  "embeds": [
    {
      "title": "🔍 Reconnaissance Report",
      "color": 65280,
      "timestamp": "2024-01-15T10:30:00",
      "fields": [
        {
          "name": "📊 Summary",
          "value": "Targets: 1\nSuccessful: 1\nFailed: 0",
          "inline": true
        }
      ]
    }
  ]
}
```

## Output Format

### JSON Output Structure

```json
{
  "scan_info": {
    "timestamp": "2024-01-15T10:30:00.123456",
    "scanner": "Webhook-based Recon Reporter v1.0.0"
  },
  "targets": [
    {
      "target": "example.com",
      "scan_type": "full",
      "start_time": "2024-01-15T10:30:00.123456",
      "dns_info": {
        "hostname": "example.com",
        "ip_addresses": ["93.184.216.34"],
        "reverse_dns": "example.com"
      },
      "port_scan": {
        "target": "93.184.216.34",
        "open_ports": [
          {
            "port": 80,
            "service": "HTTP"
          },
          {
            "port": 443,
            "service": "HTTPS"
          }
        ],
        "closed_ports": [21, 22, 23, 25],
        "scan_time": "2024-01-15T10:30:01.123456"
      },
      "http_info": {
        "target": "example.com",
        "http_status": 200,
        "https_status": 200,
        "headers": {
          "Server": "ECS (dcb/7EA3)",
          "Content-Type": "text/html; charset=UTF-8"
        },
        "server_info": "ECS (dcb/7EA3)",
        "title": "Example Domain",
        "redirects": []
      },
      "whois_info": {
        "target": "example.com",
        "registrar": "IANA",
        "creation_date": "1995-08-14",
        "expiration_date": "2024-08-13",
        "nameservers": ["a.iana-servers.net", "b.iana-servers.net"]
      },
      "status": "completed",
      "end_time": "2024-01-15T10:30:05.123456"
    }
  ],
  "summary": {
    "total_targets": 1,
    "successful_scans": 1,
    "failed_scans": 0
  }
}
```

## Security Considerations

### Ethical Use

This tool is designed for **authorized security testing only**. Users must ensure they have proper authorization before scanning any targets. Unauthorized scanning may violate:

- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in other jurisdictions

### Responsible Disclosure

- Only scan systems you own or have explicit permission to test
- Respect rate limits and avoid overwhelming target systems
- Follow responsible disclosure practices for any vulnerabilities found
- Document all testing activities for compliance purposes

### Privacy and Data Protection

- Webhook URLs may contain sensitive authentication tokens
- Scan results may contain sensitive information about network infrastructure
- Store and transmit results securely
- Consider data retention policies for scan results

## Performance and Limitations

### Performance Characteristics

- **Concurrent port scanning**: Up to 50 concurrent connections
- **DNS resolution**: Cached for efficiency
- **HTTP requests**: 10-second default timeout
- **Rate limiting**: 0.5-second delay between targets

### Known Limitations

- **WHOIS dependency**: Requires system `whois` command
- **Network timeouts**: May miss services with slow response times
- **Webhook limits**: Discord/Slack have rate limits for webhook messages
- **Large target lists**: Consider breaking into smaller batches for very large scans
- **Firewall detection**: May not detect all filtered ports accurately

### Troubleshooting

**Common Issues:**

1. **WHOIS command not found**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install whois
   
   # CentOS/RHEL
   sudo yum install whois
   
   # macOS
   brew install whois
   ```

2. **Webhook delivery failures**
   - Verify webhook URL is correct
   - Check network connectivity
   - Ensure webhook service is not rate-limiting
   - Test with `--no-webhook` flag first

3. **Permission denied errors**
   - Ensure script has execute permissions
   - Check file paths for target files and output files
   - Verify network permissions for scanning

4. **Timeout errors**
   - Increase timeout with `--timeout` parameter
   - Check network connectivity to targets
   - Consider firewall or network filtering

## Development and Contribution

### Project Structure

```
webhook_recon_reporter.py    # Main script
README.md                   # This documentation
requirements.txt           # Python dependencies (optional)
examples/                  # Example target files and configurations
```

### Adding New Features

The script is designed to be extensible. Key areas for enhancement:

- **Additional scan types**: Add new reconnaissance methods
- **Output formats**: Support for XML, CSV, or other formats
- **Database integration**: Store results in databases
- **Advanced reporting**: Enhanced webhook formatting
- **Authentication**: Support for authenticated HTTP scanning

### Code Style

- Follow PEP 8 Python style guidelines
- Include comprehensive docstrings
- Add type hints where appropriate
- Maintain backward compatibility

## Examples and Use Cases

### Penetration Testing

```bash
# Initial reconnaissance phase
python webhook_recon_reporter.py --target-file scope.txt --webhook-url $DISCORD_WEBHOOK --scan-type full --output initial_recon.json

# Quick port scan verification
python webhook_recon_reporter.py --target 192.168.1.0/24 --webhook-url $SLACK_WEBHOOK --scan-type port-only
```

### Infrastructure Monitoring

```bash
# Monitor external services
python webhook_recon_reporter.py --target-file production_services.txt --webhook-url $WEBHOOK --scan-type web-only --output monitoring.json

# Regular security checks
python webhook_recon_reporter.py --target company.com --webhook-url $WEBHOOK --scan-type basic
```

### Security Audits

```bash
# Comprehensive audit
python webhook_recon_reporter.py --target-file audit_scope.txt --webhook-url $WEBHOOK --scan-type full --output audit_results.json --timeout 30
```

## License

MIT License

Copyright (c) 2024 Webhook-based Recon Reporter

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

### Version 1.0.0 (2024-01-15)
- Initial release
- Basic reconnaissance capabilities
- Webhook integration
- Multi-threading support
- Comprehensive error handling
- JSON output format

## Support and Contact

For issues, feature requests, or questions:

- Create an issue in the project repository
- Follow responsible disclosure practices for security issues
- Provide detailed information about your environment and use case

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors are not responsible for any misuse of this tool or any damages resulting from its use.

Always obtain proper authorization before scanning any systems you do not own or have explicit permission to test.