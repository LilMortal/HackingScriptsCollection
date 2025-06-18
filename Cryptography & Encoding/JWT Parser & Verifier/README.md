# JWT Parser & Verifier

A comprehensive command-line tool for parsing, validating, and verifying JSON Web Tokens (JWTs). This tool supports multiple algorithms including HMAC-based (HS256, HS384, HS512) and asymmetric algorithms (RS256, RS384, RS512, ES256, ES384, ES512).

## Features

- 🔍 **Parse JWT tokens** without verification to inspect headers and payloads
- 🔐 **Verify JWT signatures** using secrets or public keys
- ⏰ **Validate time-based claims** (exp, nbf, iat) with configurable leeway
- 📁 **Multiple input methods** - direct token input or from file
- 🎨 **Flexible output formats** - formatted display, raw JSON, or quiet mode
- 🛡️ **Comprehensive error handling** with detailed error messages
- 📋 **Human-readable timestamps** for time-based claims
- ⚠️ **Expiration warnings** for tokens nearing expiration

## Supported Algorithms

### HMAC Algorithms (Built-in)
- **HS256** - HMAC using SHA-256
- **HS384** - HMAC using SHA-384  
- **HS512** - HMAC using SHA-512

### Asymmetric Algorithms (Requires cryptography library)
- **RS256, RS384, RS512** - RSA signature with SHA-256/384/512
- **ES256, ES384, ES512** - ECDSA signature with SHA-256/384/512

## Installation

### Prerequisites
- Python 3.6 or higher

### Basic Installation
The script works with Python's standard library for HMAC algorithms:

```bash
# Clone or download the script
curl -O https://raw.githubusercontent.com/your-repo/jwt_parser.py
chmod +x jwt_parser.py
```

### Full Installation (Recommended)
For RSA and ECDSA algorithm support, install the cryptography library:

```bash
pip install cryptography
```

Or install from requirements.txt:

```bash
# Create requirements.txt
echo "cryptography>=3.0.0" > requirements.txt
pip install -r requirements.txt
```

## Usage

### Basic Syntax
```bash
python jwt_parser.py [--token TOKEN | --token-file FILE] [--secret SECRET | --public-key KEY_FILE] [OPTIONS]
```

### Command-Line Options

#### Token Input (Required - choose one)
- `--token, -t TOKEN` - JWT token string
- `--token-file, -f FILE` - File containing JWT token

#### Verification Keys (Optional - choose one)
- `--secret, -s SECRET` - Secret key for HMAC algorithms
- `--public-key, -k FILE` - Path to public key file for RSA/ECDSA

#### Time Verification Options
- `--no-verify-exp` - Skip expiration time verification
- `--no-verify-nbf` - Skip not-before time verification  
- `--leeway SECONDS` - Allowed time drift in seconds (default: 0)

#### Output Options
- `--quiet, -q` - Only output payload (useful for scripting)
- `--raw` - Output raw JSON without formatting
- `--help, -h` - Show help message

## Examples

### 1. Parse JWT Without Verification
```bash
# Inspect JWT structure without verifying signature
python jwt_parser.py --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

### 2. Verify JWT with Secret Key (HMAC)
```bash
# Verify HS256 JWT with secret
python jwt_parser.py \
  --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  --secret "your-256-bit-secret"
```

### 3. Verify JWT with Public Key (RSA)
```bash
# Verify RS256 JWT with public key file
python jwt_parser.py \
  --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." \
  --public-key public_key.pem
```

### 4. Read JWT from File
```bash
# Store JWT in file and verify
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." > token.txt
python jwt_parser.py --token-file token.txt --secret "your-secret"
```

### 5. Skip Time Validation
```bash
# Verify signature but ignore expiration
python jwt_parser.py \
  --token "expired-jwt-token..." \
  --secret "your-secret" \
  --no-verify-exp
```

### 6. Allow Time Leeway
```bash
# Allow 30 seconds of clock drift
python jwt_parser.py \
  --token "jwt-token..." \
  --secret "your-secret" \
  --leeway 30
```

### 7. Scripting Mode
```bash
# Get only the payload for scripting
python jwt_parser.py --token "jwt-token..." --secret "secret" --quiet
```

### 8. Raw JSON Output
```bash
# Get raw JSON output
python jwt_parser.py --token "jwt-token..." --raw
```

## Sample Output

### Successful Verification
```
✅ JWT signature verified successfully!

==================================================
JWT HEADER:
==================================================
{
  "alg": "HS256",
  "typ": "JWT"
}

==================================================
JWT PAYLOAD:
==================================================
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1916239022
}

==================================================
TIME CLAIMS (Human Readable):
==================================================
Issued At: 2018-01-18 01:30:22 UTC (1516239022)
Expires At: 2030-09-18 01:30:22 UTC (1916239022)
```

### Verification Failure
```
❌ JWT Verification Failed: Invalid signature
Token information (unverified):
[Token details displayed...]
```

### Expired Token
```
❌ JWT Verification Failed: Token has expired
Token information (unverified):
[Token details with expiration warning...]
```

## Public Key Formats

The tool accepts public keys in PEM format:

### RSA Public Key Example
```pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf+eyCrGE6Wv0/wkrHwCMHGLB1e2BKUgzP7k...
-----END PUBLIC KEY-----
```

### ECDSA Public Key Example  
```pem
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQVlKgmUt7fLc2IWl3bJJgJx7sQXd
KFqVHqCPt5Ev2LO5nJgN9r6AyI2+2aX1X9GrJ2xIyJ1+1LxPtN9DqkD4...
-----END PUBLIC KEY-----
```

## Error Handling

The tool provides detailed error messages for common issues:

- **Invalid JWT format** - Malformed tokens or incorrect base64url encoding
- **Unsupported algorithms** - Algorithms not supported by the tool
- **Missing keys** - When verification requires a key but none provided
- **Invalid signatures** - When signature verification fails
- **Expired tokens** - When current time exceeds token expiration
- **Invalid time claims** - When nbf (not before) time hasn't been reached
- **File errors** - Issues reading token files or public key files

## Security Considerations

### ⚠️ Important Security Notes

1. **Secret Key Security**: Never hardcode secrets in scripts or share them in version control
2. **Token Storage**: Avoid logging or storing JWT tokens in plain text
3. **Time Validation**: Always verify time-based claims (exp, nbf) unless specifically disabled
4. **Algorithm Verification**: Be aware that the 'none' algorithm bypasses signature verification
5. **Key Management**: Use proper key rotation and secure key storage practices

### Ethical Use Guidelines

- Only parse/verify JWTs that you own or have explicit permission to analyze
- Do not use this tool to attempt unauthorized access to systems
- Respect rate limits and terms of service when testing tokens
- Use appropriate security measures when handling sensitive tokens

## Development

### Code Structure
- `JWTParser` class handles all JWT operations
- Modular design with separate methods for different algorithms
- Comprehensive error handling with custom exception classes
- Type hints for better code documentation

### Contributing
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure code follows PEP 8 style guidelines
5. Submit a pull request

### Testing
```bash
# Run basic tests
python -m doctest jwt_parser.py

# Test with sample tokens
python jwt_parser.py --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
```

## Troubleshooting

### Common Issues

**"cryptography library required for RSA verification"**
- Install: `pip install cryptography`

**"Failed to load public key"**
- Ensure key file exists and is in PEM format
- Check file permissions

**"Invalid JWT format"**
- Verify token has three parts separated by dots
- Check for proper base64url encoding

**"Unsupported algorithm"**
- Verify algorithm is in supported list
- Install cryptography for RSA/ECDSA support

## Dependencies

### Required (Built-in)
- `argparse` - Command-line argument parsing
- `base64` - Base64 encoding/decoding
- `hashlib` - Hash algorithms
- `hmac` - HMAC operations
- `json` - JSON parsing
- `time` - Time operations
- `datetime` - Date/time handling

### Optional
- `cryptography>=3.0.0` - RSA and ECDSA algorithm support

## License

MIT License

Copyright (c) 2024 JWT Parser & Verifier

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

### v1.0.0
- Initial release
- Support for HMAC algorithms (HS256, HS384, HS512)
- Support for RSA algorithms (RS256, RS384, RS512)  
- Support for ECDSA algorithms (ES256, ES384, ES512)
- Command-line interface with argparse
- Time-based claim validation
- Multiple output formats
- Comprehensive error handling

## Support

For issues, questions, or contributions:
- Check existing issues in the repository
- Create detailed bug reports with sample tokens (anonymized)
- Include Python version and cryptography library version in reports

## Related Tools

- [jwt.io](https://jwt.io/) - Online JWT debugger
- [PyJWT](https://github.com/jpadilla/pyjwt) - Python JWT library
- [python-jose](https://github.com/mpdavis/python-jose) - JavaScript Object Signing and Encryption library

---

**Note**: This tool is designed for development, testing, and educational purposes. Always follow security best practices when handling JWTs in production environments.
