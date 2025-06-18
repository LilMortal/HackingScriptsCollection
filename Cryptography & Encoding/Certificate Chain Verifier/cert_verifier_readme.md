# Certificate Chain Verifier

A comprehensive Python tool for validating SSL/TLS certificate chains from various sources including websites, files, and raw certificate data. This tool is essential for security auditing, troubleshooting certificate issues, and ensuring proper SSL/TLS configuration.

## Features

- ✅ **URL Verification**: Verify certificate chains from live websites
- ✅ **File Verification**: Validate certificates from PEM files
- ✅ **Custom CA Bundles**: Support for custom Certificate Authority bundles
- ✅ **Detailed Analysis**: Extract comprehensive certificate information
- ✅ **Expiration Checking**: Identify expired certificates and upcoming expirations
- ✅ **Hostname Validation**: Verify hostname matching including wildcard support
- ✅ **Chain Validation**: Validate certificate chain integrity
- ✅ **Export Functionality**: Save certificate chains to files
- ✅ **Multiple Output Formats**: Human-readable and JSON output
- ✅ **Verbose Logging**: Detailed information for troubleshooting

## Requirements

- Python 3.6 or higher
- OpenSSL (optional, for enhanced certificate parsing)

## Installation

### Basic Installation

1. **Download the script**:
   ```bash
   wget https://raw.githubusercontent.com/your-repo/cert_chain_verifier.py
   # or
   curl -O https://raw.githubusercontent.com/your-repo/cert_chain_verifier.py
   ```

2. **Make it executable**:
   ```bash
   chmod +x cert_chain_verifier.py
   ```

### Enhanced Installation (with OpenSSL)

For the best experience, ensure OpenSSL is installed on your system:

**Ubuntu/Debian**:
```bash
sudo apt-get update
sudo apt-get install openssl
```

**CentOS/RHEL/Fedora**:
```bash
sudo yum install openssl
# or for newer versions
sudo dnf install openssl
```

**macOS**:
```bash
brew install openssl
```

**Windows**:
- Download and install OpenSSL from [Win32/Win64 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)
- Ensure `openssl.exe` is in your PATH

## Usage

### Basic Usage

#### Verify a Website's Certificate Chain

```bash
# Basic website verification
python cert_chain_verifier.py --url https://www.google.com

# Custom port
python cert_chain_verifier.py --url https://example.com --port 8443

# Verbose output with detailed certificate information
python cert_chain_verifier.py --url https://www.github.com --verbose
```

#### Verify Certificate from File

```bash
# Verify PEM certificate file
python cert_chain_verifier.py --file /path/to/certificate.pem

# Verbose file verification
python cert_chain_verifier.py --file certificate.pem --verbose
```

### Advanced Usage

#### Custom CA Bundle

```bash
# Use custom CA bundle
python cert_chain_verifier.py --url https://internal.company.com --ca-bundle /path/to/custom-ca-bundle.pem
```

#### Export Certificate Chain

```bash
# Export certificate chain to file
python cert_chain_verifier.py --url https://example.com --export exported_chain.pem
```

#### JSON Output

```bash
# Get results in JSON format (useful for automation)
python cert_chain_verifier.py --url https://example.com --json
```

#### Combining Options

```bash
# Comprehensive verification with export
python cert_chain_verifier.py --url https://example.com --verbose --export chain.pem --json > results.json
```

### Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--url` | URL to verify certificate chain | `--url https://example.com` |
| `--file` | Path to certificate file (PEM format) | `--file cert.pem` |
| `--port` | Custom port number (default: 443) | `--port 8443` |
| `--ca-bundle` | Path to custom CA bundle file | `--ca-bundle custom-ca.pem` |
| `--export` | Export certificate chain to file | `--export chain.pem` |
| `--verbose, -v` | Enable verbose output | `--verbose` |
| `--json` | Output results in JSON format | `--json` |

## Output Interpretation

### Verification Status

- **✓ PASSED**: Certificate chain is valid and trusted
- **✗ FAILED**: Issues found with the certificate chain

### Common Issues and Warnings

#### Issues (Will cause verification failure):
- **Certificate is expired**: The certificate has passed its expiration date
- **Hostname doesn't match**: The requested hostname doesn't match the certificate
- **Untrusted certificate**: The certificate chain cannot be verified against known CAs

#### Warnings (Won't cause failure but should be addressed):
- **Certificate expires soon**: Certificate expires within 30 days
- **Chain integrity issues**: Problems with the certificate chain structure

### Certificate Information (Verbose Mode)

When using `--verbose`, the tool displays detailed information for each certificate:

- **Subject**: The entity the certificate was issued to
- **Issuer**: The Certificate Authority that issued the certificate
- **Serial Number**: Unique identifier for the certificate
- **Validity Period**: Not Before and Not After dates
- **Signature Algorithm**: Algorithm used to sign the certificate
- **Public Key Algorithm**: Algorithm used for the public key
- **Subject Alternative Names (SAN)**: Additional hostnames covered by the certificate
- **Days until expiry**: Time remaining before certificate expires

## Examples

### Example 1: Basic Website Verification

```bash
$ python cert_chain_verifier.py --url https://www.google.com

============================================================
CERTIFICATE CHAIN VERIFICATION RESULT
============================================================
Hostname: www.google.com
Port: 443
Verification Status: ✓ PASSED
Chain Length: 3 certificate(s)
Verification Time: 2024-01-15T10:30:45.123456

✓ No issues found
```

### Example 2: Expired Certificate Detection

```bash
$ python cert_chain_verifier.py --url https://expired.badssl.com

============================================================
CERTIFICATE CHAIN VERIFICATION RESULT
============================================================
Hostname: expired.badssl.com
Port: 443
Verification Status: ✗ FAILED
Chain Length: 2 certificate(s)
Verification Time: 2024-01-15T10:31:20.654321

ISSUES (1):
  ✗ Certificate 1 is expired
```

### Example 3: Verbose Certificate Details

```bash
$ python cert_chain_verifier.py --url https://github.com --verbose

============================================================
CERTIFICATE CHAIN VERIFICATION RESULT
============================================================
Hostname: github.com
Port: 443
Verification Status: ✓ PASSED
Chain Length: 2 certificate(s)
Verification Time: 2024-01-15T10:32:15.789012

✓ No issues found

CERTIFICATE DETAILS:
----------------------------------------

Certificate 1:
  Subject: CN=github.com, O=GitHub, Inc., L=San Francisco, ST=California, C=US
  Issuer: CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1, O=DigiCert Inc, C=US
  Serial Number: 0C:E7:E0:E5:17:C1:B3:D4:1F:3E:D7:1A:09:A7:0B:96
  Not Before: 2023-05-09 00:00:00
  Not After: 2024-05-10 23:59:59
  Signature Algorithm: ecdsa-with-SHA384
  Public Key Algorithm: id-ecPublicKey
  Subject Alternative Names:
    DNS:github.com
    DNS:www.github.com
  Status: ✓ VALID (128 days remaining)

Certificate 2:
  Subject: CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1, O=DigiCert Inc, C=US
  Issuer: CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
  Serial Number: 0A:27:2D:F3:DD:CA:CC:E4:4D:C5:F6:10:C2:4E:23:29
  Not Before: 2021-04-14 00:00:00
  Not After: 2031-04-13 23:59:59
  Signature Algorithm: sha384WithRSAEncryption
  Public Key Algorithm: id-ecPublicKey
  Status: ✓ VALID (2555 days remaining)
```

### Example 4: JSON Output for Automation

```bash
$ python cert_chain_verifier.py --url https://example.com --json
{
  "hostname": "example.com",
  "port": 443,
  "verified": true,
  "certificates": [
    {
      "subject": "CN=example.com, O=Example Corp, C=US",
      "issuer": "CN=Example CA, O=Example Corp, C=US",
      "serial_number": "1A:2B:3C:4D:5E:6F",
      "not_before": "2023-01-01T00:00:00",
      "not_after": "2024-01-01T23:59:59",
      "signature_algorithm": "sha256WithRSAEncryption",
      "public_key_algorithm": "rsaEncryption",
      "san_list": ["DNS:example.com", "DNS:www.example.com"],
      "is_expired": false,
      "days_until_expiry": 200
    }
  ],
  "chain_length": 2,
  "verification_details": {
    "verified": true,
    "issues": [],
    "warnings": []
  },
  "timestamp": "2024-01-15T10:33:00.123456"
}
```

## Use Cases

### Security Auditing

- **Certificate Expiration Monitoring**: Set up automated checks to monitor certificate expiration dates
- **Certificate Chain Validation**: Ensure proper certificate chain configuration
- **Compliance Verification**: Verify certificates meet organizational security standards

### DevOps and System Administration

- **CI/CD Pipeline Integration**: Integrate certificate validation into deployment pipelines
- **Infrastructure Monitoring**: Monitor certificate health across multiple services
- **Troubleshooting**: Debug SSL/TLS connection issues

### Development and Testing

- **Local Development**: Verify certificates in development environments
- **Testing**: Validate certificate configurations before production deployment
- **Certificate Management**: Maintain and verify certificate inventories

## Troubleshooting

### Common Issues

#### "No certificate chain received"
- **Cause**: The server didn't provide a certificate chain
- **Solution**: Check if the server is properly configured with SSL/TLS

#### "Hostname doesn't match certificate"
- **Cause**: The certificate doesn't include the requested hostname
- **Solution**: Verify the certificate includes the correct hostnames in Subject or SAN fields

#### "OpenSSL not available"
- **Cause**: OpenSSL is not installed or not in PATH
- **Impact**: Limited certificate parsing capabilities
- **Solution**: Install OpenSSL for enhanced functionality

#### Connection timeouts
- **Cause**: Network connectivity issues or firewall restrictions
- **Solution**: Check network connectivity and firewall rules

### Debug Mode

For detailed troubleshooting, use verbose mode:

```bash
python cert_chain_verifier.py --url https://example.com --verbose
```

This will provide detailed logging information about the verification process.

## Integration Examples

### Bash Script Integration

```bash
#!/bin/bash
# Check multiple websites
WEBSITES=("https://example.com" "https://google.com" "https://github.com")

for url in "${WEBSITES[@]}"; do
    echo "Checking $url..."
    python cert_chain_verifier.py --url "$url" --json > "result_$(basename $url).json"
    
    if [ $? -eq 0 ]; then
        echo "✓ $url passed verification"
    else
        echo "✗ $url failed verification"
    fi
done
```

### Python Script Integration

```python
import subprocess
import json

def check_certificate(url):
    """Check certificate for a given URL."""
    try:
        result = subprocess.run([
            'python', 'cert_chain_verifier.py', 
            '--url', url, '--json'
        ], capture_output=True, text=True, check=True)
        
        return json.loads(result.stdout)
    except subprocess.CalledProcessError:
        return None

# Usage
result = check_certificate('https://example.com')
if result and result['verified']:
    print(f"Certificate for {result['hostname']} is valid")
else:
    print("Certificate verification failed")
```

### Monitoring Integration

For continuous monitoring, you can integrate this tool with monitoring systems like:

- **Nagios/Icinga**: Create custom check scripts
- **Prometheus**: Use as an exporter for certificate metrics
- **Zabbix**: Create custom monitoring items
- **AWS CloudWatch**: Integrate with Lambda functions

## Security Considerations

### Ethical Use

This tool is designed for legitimate security auditing and system administration purposes. Please ensure you:

- Only verify certificates for domains you own or have permission to test
- Respect rate limits and avoid excessive requests to external services
- Follow your organization's security policies and procedures

### Privacy

- The tool connects to external servers to retrieve certificates
- No sensitive data is stored or transmitted beyond the certificate verification process
- Be cautious when using custom CA bundles that might contain sensitive information

### Limitations

- **Network Dependencies**: Requires network connectivity for URL verification
- **OpenSSL Dependency**: Enhanced features require OpenSSL installation
- **Certificate Parsing**: Some advanced certificate extensions may not be fully parsed
- **Performance**: Large certificate chains or slow networks may impact performance

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Setup

1. Clone the repository
2. Install development dependencies
3. Run tests
4. Submit pull requests

### Reporting Issues

When reporting issues, please include:

- Python version
- Operating system
- OpenSSL version (if applicable)
- Complete error messages
- Steps to reproduce the issue

## License

MIT License

Copyright (c) 2024 Certificate Chain Verifier

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
- URL and file-based certificate verification
- Custom CA bundle support
- Certificate chain validation
- Hostname verification
- Expiration checking
- Export functionality
- JSON output support
- Verbose logging

## Support

For support, please:

1. Check the troubleshooting section
2. Search existing issues
3. Create a new issue with detailed information

## Acknowledgments

- Python SSL module for certificate handling
- OpenSSL for advanced certificate parsing
- The security community for best practices and standards