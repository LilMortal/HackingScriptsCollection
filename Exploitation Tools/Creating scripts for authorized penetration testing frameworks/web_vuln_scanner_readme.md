# Authorized Web Vulnerability Scanner

A legitimate penetration testing tool designed for authorized security assessments of web applications. This scanner performs various security checks including directory enumeration, HTTP header analysis, SSL/TLS configuration assessment, and common vulnerability detection.

## ⚠️ LEGAL DISCLAIMER

**This tool is for authorized security testing ONLY.** You must:
- Own the target system, OR
- Have explicit written permission from the system owner

Unauthorized scanning is illegal and unethical. The developers are not responsible for misuse of this tool.

## Features

- **Security Header Analysis**: Checks for missing or misconfigured security headers
- **SSL/TLS Assessment**: Analyzes SSL certificate and configuration
- **Directory Enumeration**: Discovers common directories and files
- **Common Vulnerability Detection**: Identifies potential security issues
- **Multi-threaded Scanning**: Concurrent requests for faster scanning
- **JSON Output**: Structured results for further analysis
- **Customizable Scans**: Basic or full scan modes

## Requirements

- Python 3.6 or higher
- Internet connection for target scanning

## Installation

1. **Clone or download the script**:
   ```bash
   wget https://raw.githubusercontent.com/your-repo/web_vuln_scanner.py
   # or
   curl -O https://raw.githubusercontent.com/your-repo/web_vuln_scanner.py
   ```

2. **Install required dependencies**:
   ```bash
   pip install requests urllib3
   ```

   Or install from requirements.txt:
   ```bash
   pip install -r requirements.txt
   ```

3. **Make the script executable** (Linux/macOS):
   ```bash
   chmod +x web_vuln_scanner.py
   ```

### Dependencies

The script uses the following Python packages:
- `requests`: For HTTP requests
- `urllib3`: For advanced HTTP functionality
- Standard library modules: `argparse`, `json`, `ssl`, `socket`, `threading`, `concurrent.futures`

## Usage

### Basic Usage

```bash
python web_vuln_scanner.py -u https://example.com --confirm
```

### Advanced Usage

```bash
# Full scan with custom threading and output
python web_vuln_scanner.py -u https://example.com --scan-type full --threads 10 --output results.json --confirm

# Basic scan with custom timeout
python web_vuln_scanner.py -u http://testsite.local --timeout 15 --confirm
```

### Command Line Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| `--url` | `-u` | Yes | Target URL to scan |
| `--output` | `-o` | No | Output file for results (JSON format) |
| `--scan-type` | | No | Type of scan: `basic` or `full` (default: basic) |
| `--threads` | | No | Number of concurrent threads (default: 5, max: 50) |
| `--timeout` | | No | Request timeout in seconds (default: 10, max: 60) |
| `--confirm` | | Yes | Confirm authorization to test target |

### Scan Types

- **Basic Scan**: Security headers, SSL analysis, common vulnerabilities
- **Full Scan**: All basic checks plus directory enumeration

## Output

The scanner provides color-coded console output:
- 🔴 **HIGH**: Critical security issues
- 🟡 **MEDIUM**: Important security concerns
- 🟢 **LOW**: Minor security improvements
- 🔵 **INFO**: General information

### Sample Output

```
Starting basic vulnerability scan on https://example.com
Scan started at: 2024-01-15 10:30:00
============================================================

[INFO] Analyzing security headers for https://example.com
[MEDIUM] Security Headers: Missing security headers: X-Content-Type-Options, X-Frame-Options
[LOW] Information Disclosure: Server information disclosed: Server: nginx/1.18.0

[INFO] Analyzing SSL/TLS configuration
[INFO] SSL Configuration: TLS Version: TLSv1.3, Cipher: TLS_AES_256_GCM_SHA384

[INFO] Checking for common vulnerabilities
[MEDIUM] Clickjacking: No X-Frame-Options header found - potential clickjacking vulnerability

============================================================
Scan completed in 3.45 seconds
Total findings: 3
Results saved to: results.json
```

### JSON Output Format

```json
[
  {
    "timestamp": "2024-01-15T10:30:01.123456",
    "severity": "MEDIUM",
    "category": "Security Headers",
    "message": "Missing security headers: X-Content-Type-Options",
    "target": "https://example.com",
    "details": {
      "missing_headers": ["X-Content-Type-Options"]
    }
  }
]
```

## Security Checks Performed

### 1. HTTP Security Headers
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Strict-Transport-Security (HSTS)
- Referrer-Policy
- Permissions-Policy

### 2. SSL/TLS Configuration
- Certificate expiration
- TLS version
- Cipher suite analysis
- Certificate chain validation

### 3. Information Disclosure
- Server headers
- Technology stack disclosure
- Version information

### 4. Directory Enumeration (Full Scan)
- Admin panels
- Backup files
- Configuration files
- Development directories
- API endpoints

### 5. Common Vulnerabilities
- Clickjacking protection
- Accessible backup files
- Configuration file exposure

## Examples

### Testing a Local Development Server
```bash
python web_vuln_scanner.py -u http://localhost:8080 --confirm
```

### Comprehensive Scan with Results Export
```bash
python web_vuln_scanner.py \
  -u https://your-authorized-target.com \
  --scan-type full \
  --threads 15 \
  --timeout 20 \
  --output security_assessment.json \
  --confirm
```

### Quick Security Header Check
```bash
python web_vuln_scanner.py -u https://example.com --scan-type basic --confirm
```

## Best Practices

1. **Always obtain proper authorization** before scanning
2. **Use reasonable thread counts** to avoid overwhelming the target
3. **Respect rate limits** and implement delays if needed
4. **Save results** for documentation and tracking
5. **Combine with other tools** for comprehensive assessment

## Limitations

- **Authentication**: Does not handle authenticated sessions
- **Complex Vulnerabilities**: May not detect application-specific issues
- **False Positives**: Manual verification of findings is recommended
- **Rate Limiting**: May be blocked by WAFs or rate limiting

## Troubleshooting

### Common Issues

1. **Connection Timeouts**:
   - Increase timeout value with `--timeout`
   - Reduce thread count with `--threads`

2. **SSL Certificate Errors**:
   - The scanner accepts self-signed certificates for testing
   - Check network connectivity

3. **Permission Denied**:
   - Ensure you have proper authorization
   - Some endpoints may require authentication

### Error Messages

- `Invalid URL format`: Check URL syntax (include http:// or https://)
- `Unable to connect to target`: Verify target is accessible
- `Thread count must be between 1 and 50`: Adjust --threads parameter

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License

Copyright (c) 2024 Web Vulnerability Scanner

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

## Ethical Use Statement

This tool is designed to help security professionals and system administrators
identify potential vulnerabilities in systems they are authorized to test. 

**By using this tool, you agree to:**
- Only scan systems you own or have explicit permission to test
- Follow responsible disclosure practices for any vulnerabilities found
- Comply with all applicable laws and regulations
- Use the tool for defensive security purposes only

**Prohibited uses include:**
- Scanning systems without authorization
- Using findings for malicious purposes
- Violating terms of service of target systems
- Any illegal activities

## Support

For questions, issues, or feature requests:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the documentation

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
