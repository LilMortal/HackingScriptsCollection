# JWT Security Audit Tool

A comprehensive security audit tool for JSON Web Tokens (JWTs) that identifies common vulnerabilities and security misconfigurations.

## Description

This tool performs automated security analysis of JWT tokens to identify:

- **Algorithm vulnerabilities** (none algorithm, weak algorithms, algorithm confusion)
- **Payload security issues** (sensitive data exposure, missing claims, expiration problems)
- **Weak secrets** through brute force testing
- **Signature analysis** (entropy, length, randomness)
- **Common attack vectors** (key confusion, none algorithm bypass)

The tool provides detailed security reports with risk scoring and actionable remediation advice.

## Features

- 🔍 **Comprehensive Analysis**: Checks for 10+ different vulnerability types
- 🔐 **Brute Force Testing**: Tests for weak HMAC secrets using custom wordlists
- 📊 **Risk Scoring**: Calculates overall security risk with detailed breakdown
- 📁 **Batch Processing**: Analyze multiple tokens from files
- 📋 **Detailed Reports**: JSON output with full vulnerability details
- ⚡ **Fast Performance**: Optimized for quick security assessments
- 🛡️ **Safe Testing**: Read-only analysis, no token modification

## Installation

### Prerequisites

- Python 3.6 or higher
- pip package manager

### Install Dependencies

```bash
pip install pyjwt cryptography requests
```

Or install from requirements file:

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
pyjwt>=2.4.0
cryptography>=3.4.8
requests>=2.26.0
```

### Download Script

1. Download `jwt_audit.py` to your local machine
2. Make it executable (Unix/Linux/macOS):
   ```bash
   chmod +x jwt_audit.py
   ```

## Usage

### Basic Usage

Audit a single JWT token:
```bash
python jwt_audit.py --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

### Advanced Usage

#### Batch Processing
Analyze multiple tokens from a file:
```bash
python jwt_audit.py --file tokens.txt --output detailed_report.json
```

#### Custom Wordlist Brute Force
Use a custom wordlist for secret testing:
```bash
python jwt_audit.py --token "..." --wordlist common_secrets.txt --verbose
```

#### Analysis Only (No Brute Force)
Perform structure analysis without brute force testing:
```bash
python jwt_audit.py --token "..." --analyze-only
```

#### Verbose Output
Enable detailed logging:
```bash
python jwt_audit.py --token "..." --verbose
```

### Command Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--token` | `-t` | JWT token to audit |
| `--file` | `-f` | File containing JWT tokens (one per line) |
| `--wordlist` | `-w` | Wordlist file for brute force attacks |
| `--output` | `-o` | Output file for detailed JSON report |
| `--verbose` | `-v` | Enable verbose logging |
| `--analyze-only` | | Only analyze structure, skip brute force |
| `--no-brute-force` | | Skip brute force testing entirely |
| `--help` | `-h` | Show help message |

### Input File Formats

#### Token File Format
```
# Comments start with #
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
```

#### Wordlist Format
```
secret
password
123456
admin
test
jwt_secret
my_secret_key
```

## Security Checks

The tool performs the following security assessments:

### Critical Vulnerabilities
- **None Algorithm**: Tokens using `alg: "none"`
- **Weak Secrets**: HMAC secrets discoverable through brute force
- **Empty Signatures**: Tokens with missing signature components
- **Sensitive Data**: Personal/confidential information in payload

### High-Risk Issues
- **Weak Algorithms**: Cryptographically weak signing algorithms
- **Algorithm Confusion**: Mixed symmetric/asymmetric indicators

### Medium-Risk Issues
- **Expired Tokens**: Tokens past their expiration time
- **Missing Standard Claims**: Absence of `iss`, `sub`, `aud` claims
- **Long Token Lifetime**: Tokens valid for extended periods

### Low-Risk Issues
- **Low Entropy**: Signatures with poor randomness
- **Short Signatures**: Potentially weak signature lengths

## Output Examples

### Console Output
```
============================================================
JWT SECURITY AUDIT SUMMARY
============================================================
Risk Level: CRITICAL
Risk Score: 15/100
Total Issues: 3
  - Vulnerabilities: 2
  - Warnings: 1

CRITICAL VULNERABILITIES (1):
• Algorithm set to "none"
  Impact: Complete authentication bypass possible
  Fix: Use a secure signing algorithm (HS256, RS256, etc.)
```

### JSON Report Structure
```json
{
  "timestamp": "2025-06-18T10:30:00",
  "summary": {
    "total_issues": 3,
    "vulnerabilities": 2,
    "warnings": 1,
    "risk_score": 15,
    "risk_level": "CRITICAL"
  },
  "vulnerabilities": [
    {
      "type": "CRITICAL",
      "issue": "Algorithm set to \"none\"",
      "description": "JWT uses no signature verification",
      "impact": "Complete authentication bypass possible",
      "recommendation": "Use a secure signing algorithm"
    }
  ],
  "warnings": [...],
  "token_info": {
    "algorithm": "none",
    "token_length": 245
  }
}
```

## Ethical Use and Legal Disclaimer

**⚠️ IMPORTANT LEGAL NOTICE**

This tool is designed for:
- ✅ **Security testing of your own applications**
- ✅ **Authorized penetration testing with proper written permission**
- ✅ **Educational purposes and security research**
- ✅ **Bug bounty programs with explicit scope inclusion**

**Prohibited Uses:**
- ❌ Testing systems without explicit authorization
- ❌ Accessing systems you don't own or have permission to test
- ❌ Any illegal or unauthorized security testing

**Users are solely responsible for:**
- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Using the tool ethically and responsibly

## Security Considerations

- The tool performs **read-only analysis** and does not modify tokens
- Brute force testing uses common weak secrets only
- No network requests are made during analysis
- Sensitive data in payloads is filtered from reports
- All processing is done locally

## Limitations

- **Brute force testing** is limited to common weak secrets
- **Custom algorithms** may not be fully supported
- **Encrypted JWTs (JWE)** are not currently supported
- **Key strength analysis** is basic and heuristic-based
- **Network-based attacks** are not implemented

## Troubleshooting

### Common Issues

**ImportError: Missing dependencies**
```bash
pip install pyjwt cryptography requests
```

**Invalid JWT format**
- Ensure token has exactly 3 parts separated by dots
- Check for URL encoding issues
- Verify token is not truncated

**Permission denied**
```bash
chmod +x jwt_audit.py
```

**Large wordlist performance**
- Use smaller, targeted wordlists for better performance
- Consider using `--no-brute-force` for quick analysis

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure code follows PEP 8 style guidelines
5. Submit a pull request