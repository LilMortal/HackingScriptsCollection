# RSA Key Size Checker

A comprehensive Python tool for analyzing RSA keys and certificates to determine their key sizes and security levels. This tool helps security professionals, developers, and system administrators assess the cryptographic strength of RSA keys in various formats.

## Features

- **Multiple Input Methods**: Analyze RSA keys from PEM/DER files, SSL certificates via URL, or direct key parameters
- **Comprehensive Analysis**: Provides security level assessment, recommendations, and equivalent symmetric key strength
- **Multiple Output Formats**: Text and JSON output formats for integration with other tools
- **Network Certificate Analysis**: Directly analyze SSL/TLS certificates from live servers
- **Security Recommendations**: Based on current NIST guidelines and industry best practices
- **Detailed Key Information**: Analyze modulus, exponent, and other RSA parameters

## Security Levels

The tool categorizes RSA key sizes according to current security standards:

- **512 bits**: Critically Weak - Replace immediately
- **768 bits**: Very Weak - Replace immediately  
- **1024 bits**: Weak - Replace soon
- **2048 bits**: Adequate - Current minimum standard
- **3072 bits**: Good - Recommended for new deployments
- **4096 bits**: Strong - High security applications
- **8192 bits**: Very Strong - Maximum practical security

## Installation

### Prerequisites

- Python 3.6 or higher
- No external dependencies required (uses only Python standard library)

### Installation Steps

1. **Clone or Download**: Save the `rsa_key_checker.py` script to your local machine

2. **Make Executable** (Unix/Linux/macOS):
   ```bash
   chmod +x rsa_key_checker.py
   ```

3. **Verify Installation**:
   ```bash
   python3 rsa_key_checker.py --help
   ```

## Usage

### Basic Usage

```bash
# Analyze a certificate file
python3 rsa_key_checker.py --file certificate.pem

# Analyze a private key file
python3 rsa_key_checker.py --file private_key.pem --key-type private

# Analyze an SSL certificate from a website
python3 rsa_key_checker.py --url google.com

# Analyze a specific key size
python3 rsa_key_checker.py --key-size 2048
```

### Advanced Usage

```bash
# Analyze certificate with custom port
python3 rsa_key_checker.py --url example.com --port 8443

# Analyze RSA key from modulus and exponent
python3 rsa_key_checker.py --modulus 0x1234567890abcdef... --exponent 65537

# Get JSON output for integration
python3 rsa_key_checker.py --file cert.pem --format json

# Verbose output with detailed information
python3 rsa_key_checker.py --file cert.pem --verbose
```

### Command Line Arguments

#### Input Methods (choose one):
- `--file, -f`: Path to PEM/DER file containing RSA key or certificate
- `--url, -u`: URL/hostname to retrieve SSL certificate from
- `--key-size, -s`: Directly specify RSA key size in bits for analysis
- `--modulus, -m`: RSA modulus (as hex string or decimal)

#### Optional Arguments:
- `--port, -p`: Port for URL connections (default: 443)
- `--key-type, -t`: Type of key in file (auto, private, public, certificate)
- `--exponent, -e`: RSA public exponent (used with --modulus, default: 65537)
- `--format`: Output format (text, json)
- `--verbose, -v`: Enable verbose output
- `--help, -h`: Show help message

## Examples

### Example 1: Analyze a Certificate File
```bash
python3 rsa_key_checker.py --file /etc/ssl/certs/server.pem
```

**Output:**
```
============================================================
RSA Key Analysis Results
============================================================
Key Size: 2048 bits
Security Level: Adequate - Current minimum standard
Is Standard Size: Yes
Is Secure: Yes
Equivalent Symmetric Key Strength: ~14 bits

Recommendation:
  Acceptable for current use, consider upgrading for new deployments

Security Guidelines:
  • Minimum recommended: 2048 bits
  • Good for new deployments: 3072+ bits
  • High security applications: 4096+ bits
  • Keys under 2048 bits should be replaced immediately
```

### Example 2: Check a Website's Certificate
```bash
python3 rsa_key_checker.py --url github.com --verbose
```

### Example 3: Analyze from RSA Parameters
```bash
python3 rsa_key_checker.py --modulus 0xc2a4... --exponent 65537 --verbose
```

### Example 4: JSON Output for Automation
```bash
python3 rsa_key_checker.py --url example.com --format json | jq '.key_size'
```

## File Format Support

The tool supports various file formats:

- **PEM Files**: Certificate files, private keys, public keys
- **Certificate Files**: `.crt`, `.cer`, `.pem` files
- **Private Key Files**: `.key`, `.pem` files  
- **Network Certificates**: Live SSL/TLS certificates via HTTPS

## Integration Examples

### Shell Script Integration
```bash
#!/bin/bash
# Check multiple certificates
for cert in /etc/ssl/certs/*.pem; do
    echo "Checking $cert"
    python3 rsa_key_checker.py --file "$cert" --format json | jq '.is_secure'
done
```

### Python Integration
```python
import subprocess
import json

def check_rsa_key(file_path):
    result = subprocess.run([
        'python3', 'rsa_key_checker.py', 
        '--file', file_path, 
        '--format', 'json'
    ], capture_output=True, text=True)
    
    return json.loads(result.stdout)

# Usage
analysis = check_rsa_key('certificate.pem')
print(f"Key size: {analysis['key_size']} bits")
print(f"Is secure: {analysis['is_secure']}")
```

## Security Considerations

### What This Tool Does
- Analyzes RSA key sizes and provides security assessments
- Helps identify weak or outdated cryptographic keys
- Provides recommendations based on current security standards
- Supports multiple input formats for flexibility

### What This Tool Does NOT Do
- **Does not break or crack RSA keys** - This is a analysis tool only
- **Does not extract private key material** - Only analyzes key sizes
- **Does not perform cryptographic attacks** - Purely informational
- **Does not modify any files or keys** - Read-only analysis

### Ethical Use Guidelines
- Use only on systems and certificates you own or have permission to analyze
- Respect rate limits when analyzing certificates from public websites
- Do not use for unauthorized security testing or penetration testing
- Follow your organization's security policies when analyzing internal systems

### Limitations
- **Simplified DER Parsing**: Uses heuristic methods for key extraction (production use should consider cryptography libraries)
- **Network Timeouts**: May fail on slow or unreliable network connections
- **Certificate Chain**: Analyzes only the server certificate, not the entire chain
- **File Format Support**: Limited to common PEM/DER formats

## Troubleshooting

### Common Issues

1. **"Could not extract RSA key from file"**
   - Verify the file contains a valid RSA key or certificate
   - Try specifying the key type explicitly with `--key-type`
   - Ensure the file is in PEM or DER format

2. **"Could not retrieve certificate from URL"**
   - Check network connectivity
   - Verify the hostname and port are correct
   - Some servers may block automated certificate requests

3. **"Error parsing modulus or exponent"**
   - Ensure hex values start with '0x'
   - Verify the modulus and exponent are valid integers
   - Check for typos in long hex strings

### Debug Mode
Use the `--verbose` flag for detailed error information:
```bash
python3 rsa_key_checker.py --file problematic.pem --verbose
```

## Contributing

This tool is provided as-is for educational and professional use. If you encounter issues or have suggestions for improvements:

1. Verify the issue with the `--verbose` flag
2. Check the file format and content
3. Test with known good certificates/keys
4. Consider using established cryptographic libraries for production use

## Version History

- **v1.0.0**: Initial release with core functionality
  - PEM/DER file analysis
  - Network certificate retrieval
  - Security level assessment
  - JSON output support

## License

MIT License

Copyright (c) 2025 Claude AI Assistant

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

This tool is provided for educational and legitimate security assessment purposes only. Users are responsible for ensuring they have proper authorization before analyzing any systems or certificates. The authors assume no liability for misuse of this tool.
