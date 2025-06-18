# Slack Bot for Security Alerts

A comprehensive Python script that sends security alerts to Slack channels using webhooks. This bot supports various types of security alerts with different severity levels, customizable formatting, and detailed logging capabilities.

## Features

- **Multiple Alert Types**: Support for login failures, intrusions, malware detection, firewall alerts, vulnerabilities, and custom alerts
- **Severity Levels**: Four severity levels (low, medium, high, critical) with color-coded formatting
- **Rich Formatting**: Professional Slack message formatting with attachments, fields, and timestamps
- **Flexible Configuration**: Command-line arguments, environment variables, and JSON configuration file support
- **Comprehensive Logging**: Detailed logging to both console and file with debug mode
- **Error Handling**: Robust error handling with meaningful error messages
- **Connection Testing**: Built-in webhook connection testing functionality
- **Input Validation**: Thorough validation of all inputs and parameters

## Installation

### Prerequisites

- Python 3.6 or higher
- Internet connection for sending webhooks to Slack

### Dependencies

This script uses only Python standard libraries, so no additional packages need to be installed:

- `argparse` - Command-line argument parsing
- `json` - JSON data handling
- `urllib` - HTTP requests for webhook calls
- `logging` - Comprehensive logging functionality
- `datetime` - Timestamp generation
- `typing` - Type hints for better code documentation

### Setup

1. **Clone or download the script:**
   ```bash
   # Download the script file
   curl -O https://raw.githubusercontent.com/yourrepo/slack_security_bot.py
   
   # Or copy the script to your local system
   ```

2. **Make the script executable (Linux/macOS):**
   ```bash
   chmod +x slack_security_bot.py
   ```

3. **Set up your Slack webhook:**
   - Go to your Slack workspace
   - Navigate to Apps → Incoming Webhooks
   - Create a new webhook for your desired channel
   - Copy the webhook URL (starts with `https://hooks.slack.com/...`)

## Usage

### Basic Usage

Send a simple security alert:
```bash
python slack_security_bot.py --webhook-url "https://hooks.slack.com/your/webhook/url" \
                              --alert-type login_failure \
                              --message "Multiple failed login attempts detected" \
                              --severity high
```

### Advanced Usage Examples

**Intrusion Detection Alert:**
```bash
python slack_security_bot.py --webhook-url "https://hooks.slack.com/your/webhook/url" \
                              --alert-type intrusion \
                              --message "Suspicious activity detected from external IP" \
                              --severity critical \
                              --source "192.168.1.100" \
                              --details '{"user": "admin", "attempts": 5, "location": "Unknown"}'
```

**Malware Detection Alert:**
```bash
python slack_security_bot.py --webhook-url "https://hooks.slack.com/your/webhook/url" \
                              --alert-type malware \
                              --message "Malware detected and quarantined" \
                              --severity critical \
                              --source "workstation-01" \
                              --details '{"file": "suspicious.exe", "scanner": "ClamAV", "action": "quarantined"}'
```

**Custom Alert with Custom Title:**
```bash
python slack_security_bot.py --webhook-url "https://hooks.slack.com/your/webhook/url" \
                              --alert-type custom \
                              --message "Database backup verification failed" \
                              --severity medium \
                              --custom-title "🗄️ Database Alert" \
                              --details '{"database": "production", "last_backup": "2024-01-15"}'
```

### Environment Variable Usage

Set your webhook URL as an environment variable to avoid exposing it in command history:

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/your/webhook/url"

python slack_security_bot.py --alert-type firewall \
                              --message "Unusual traffic pattern detected" \
                              --severity medium
```

### Configuration File Usage

Create a JSON configuration file (`config.json`):
```json
{
    "webhook_url": "https://hooks.slack.com/your/webhook/url",
    "alert_type": "custom",
    "severity": "medium",
    "debug": false
}
```

Use the configuration file:
```bash
python slack_security_bot.py --config-file config.json \
                              --message "Scheduled security scan completed" \
                              --details '{"scanned_files": 15420, "threats_found": 0}'
```

### Testing the Connection

Test your webhook URL before sending real alerts:
```bash
python slack_security_bot.py --webhook-url "https://hooks.slack.com/your/webhook/url" --test
```

### Debug Mode

Enable detailed logging for troubleshooting:
```bash
python slack_security_bot.py --webhook-url "https://hooks.slack.com/your/webhook/url" \
                              --alert-type login_failure \
                              --message "Debug test message" \
                              --debug
```

## Command-Line Arguments

### Required Arguments
- `--webhook-url`: Slack webhook URL (can also use `SLACK_WEBHOOK_URL` environment variable)

### Alert Configuration
- `--alert-type`: Type of security alert
  - Options: `login_failure`, `intrusion`, `malware`, `firewall`, `vulnerability`, `custom`
  - Default: `custom`
- `--message`: Alert message content (required unless using `--test`)
- `--severity`: Alert severity level
  - Options: `low`, `medium`, `high`, `critical`
  - Default: `medium`

### Optional Details
- `--source`: Source of the alert (IP address, hostname, etc.)
- `--details`: Additional alert details as JSON string
- `--custom-title`: Custom title for the alert

### Utility Options
- `--test`: Send a test message to verify webhook connection
- `--debug`: Enable debug logging
- `--config-file`: Path to JSON configuration file

## Alert Types and Default Formatting

| Alert Type | Title | Emoji | Default Severity |
|------------|-------|-------|------------------|
| `login_failure` | 🔐 Login Failure Alert | :warning: | medium |
| `intrusion` | 🚨 Intrusion Detection Alert | :rotating_light: | high |
| `malware` | 🦠 Malware Detection Alert | :biohazard_sign: | critical |
| `firewall` | 🛡️ Firewall Alert | :shield: | medium |
| `vulnerability` | 🔍 Vulnerability Alert | :mag: | high |
| `custom` | ⚠️ Security Alert | :exclamation: | medium |

## Integration Examples

### Integration with Log Monitoring

```bash
#!/bin/bash
# Monitor auth.log for failed logins
tail -f /var/log/auth.log | grep "Failed password" | while read line; do
    python slack_security_bot.py --alert-type login_failure \
                                  --message "Failed login detected: $line" \
                                  --severity medium
done
```

### Integration with Cron Jobs

```bash
# Add to crontab for daily security reports
0 9 * * * python /path/to/slack_security_bot.py --alert-type custom \
                 --message "Daily security scan completed successfully" \
                 --severity low \
                 --custom-title "📊 Daily Security Report"
```

### Integration with Python Scripts

```python
import subprocess
import json

def send_security_alert(alert_type, message, severity="medium", details=None):
    """Send a security alert using the Slack bot."""
    cmd = [
        "python", "slack_security_bot.py",
        "--alert-type", alert_type,
        "--message", message,
        "--severity", severity
    ]
    
    if details:
        cmd.extend(["--details", json.dumps(details)])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0

# Usage example
details = {"ip": "192.168.1.100", "user": "admin", "attempts": 3}
success = send_security_alert("login_failure", "Multiple failed logins", "high", details)
```

## Logging

The script creates detailed logs in the following locations:

- **Console Output**: Real-time status messages and errors
- **Log File**: `slack_security_bot.log` in the same directory as the script

Log entries include:
- Timestamp
- Log level (INFO, ERROR, DEBUG)
- Detailed message about the operation

## Error Handling

The script includes comprehensive error handling for:

- **Network Issues**: Connection timeouts, DNS failures
- **Invalid URLs**: Malformed webhook URLs
- **Authentication**: Invalid webhook credentials
- **Input Validation**: Invalid alert types, severities, or JSON data
- **Rate Limiting**: Slack API rate limit handling

All errors are logged with detailed messages to help with troubleshooting.

## Security Considerations

### Best Practices

1. **Webhook URL Security**:
   - Store webhook URLs as environment variables or in secure configuration files
   - Avoid exposing webhook URLs in command history or logs
   - Regularly rotate webhook URLs if compromised

2. **Message Content**:
   - Avoid including sensitive information (passwords, keys) in alert messages
   - Sanitize user input before including in alerts
   - Consider using generic messages for highly sensitive alerts

3. **Access Control**:
   - Restrict access to the script and configuration files
   - Use dedicated Slack channels for security alerts
   - Implement proper file permissions (600 for config files)

### Compliance Notes

- This tool sends data to Slack (external service) - ensure compliance with your organization's data policies
- Log files may contain sensitive information - implement appropriate log rotation and retention policies
- Consider encryption for configuration files containing webhook URLs

## Limitations

- **Rate Limits**: Slack has rate limits for incoming webhooks (1 message per second)
- **Message Size**: Slack messages have size limits (approximately 4000 characters)
- **Attachment Limits**: Maximum of 100 attachments per message
- **Network Dependency**: Requires internet connectivity to reach Slack servers

## Troubleshooting

### Common Issues

**"Invalid Slack webhook URL format"**:
- Ensure URL starts with `https://hooks.slack.com/`
- Verify the webhook is active in your Slack workspace

**"Network error sending alert"**:
- Check internet connectivity
- Verify firewall settings allow HTTPS traffic
- Test webhook URL manually

**"JSON encoding error"**:
- Validate JSON syntax in `--details` parameter
- Use online JSON validators to check format

**"Failed to send alert. Status: 404"**:
- Webhook URL may be invalid or expired
- Regenerate webhook in Slack settings

### Debug Mode

Enable debug mode for detailed troubleshooting:
```bash
python slack_security_bot.py --debug --test
```

This will show:
- Detailed network requests
- JSON payload contents
- Step-by-step execution flow

## Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly with various alert types
5. Submit a pull request

### Code Style

- Follow PEP 8 Python style guidelines
- Use type hints for all function parameters
- Include comprehensive docstrings
- Maintain backward compatibility

## License

MIT License

Copyright (c) 2024 Security Team

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

### Version 1.0.0
- Initial release
- Support for multiple alert types
- Comprehensive error handling
- Configuration file support
- Debug logging capabilities

---

For additional support or feature requests, please open an issue in the project repository.
