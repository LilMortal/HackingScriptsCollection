# Educational Security Tools

A Python-based collection of educational tools for learning cybersecurity concepts in a safe, controlled environment. This script demonstrates password analysis, cryptographic hashing, secure random generation, and basic cipher implementations.

## Features

- **Password Strength Analysis**: Comprehensive password evaluation with detailed feedback
- **Secure Password Generation**: Cryptographically secure password generation with customizable options
- **Hash Demonstrations**: Multiple hashing algorithms (MD5, SHA-1, SHA-256, SHA-512) with comparison tools
- **Simple Cipher Examples**: Educational implementations of Caesar cipher and XOR cipher
- **Secure Token Generation**: Generate cryptographically secure tokens in various formats

## Installation

### Prerequisites
- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

### Setup
1. Download the `edu_security_tools.py` script
2. Make it executable (Linux/macOS):
   ```bash
   chmod +x edu_security_tools.py
   ```

## Usage

The script provides several commands, each with specific functionality:

### Password Analysis
Analyze the strength of a password and get improvement suggestions:

```bash
python edu_security_tools.py password-check --password "MyPassword123!"
```

**Output includes:**
- Password strength score and level
- Security checks (length, character variety, common passwords, etc.)
- Specific suggestions for improvement

### Password Generation
Generate cryptographically secure passwords:

```bash
# Generate a 16-character password
python edu_security_tools.py generate-password --length 16

# Generate 5 passwords without special symbols
python edu_security_tools.py generate-password --length 12 --no-symbols --count 5

# Generate password allowing ambiguous characters
python edu_security_tools.py generate-password --length 20 --allow-ambiguous
```

**Options:**
- `--length`: Password length (default: 12)
- `--no-symbols`: Exclude special characters
- `--allow-ambiguous`: Include potentially confusing characters (0, O, l, 1, etc.)
- `--count`: Number of passwords to generate

### Hash Demonstrations
Demonstrate various hashing algorithms:

```bash
# Hash a single text
python edu_security_tools.py hash-demo --text "Hello World" --algorithm sha256

# Compare hashes of two texts
python edu_security_tools.py hash-demo --text "Hello" --compare "hello" --algorithm md5
```

**Supported algorithms:**
- `md5` (for educational purposes - not secure)
- `sha1` (deprecated for security)
- `sha256` (recommended)
- `sha512` (high security)

### Cipher Demonstrations
Educational cipher implementations:

```bash
# Caesar cipher encryption
python edu_security_tools.py cipher-demo --text "Hello World" --cipher caesar --shift 3

# Caesar cipher decryption
python edu_security_tools.py cipher-demo --text "Khoor Zruog" --cipher caesar --shift 3 --decrypt

# XOR cipher (educational only)
python edu_security_tools.py cipher-demo --text "Secret Message" --cipher xor --key "mykey"
```

### Token Generation
Generate secure tokens for various purposes:

```bash
# Generate URL-safe token
python edu_security_tools.py generate-token --length 32 --format urlsafe

# Generate hexadecimal token
python edu_security_tools.py generate-token --length 16 --format hex
```

## Educational Value

This tool is designed to help users understand:

1. **Password Security**: What makes a password strong or weak
2. **Cryptographic Hashing**: How hash functions work and their properties
3. **Secure Random Generation**: Importance of cryptographically secure randomness
4. **Basic Cryptography**: Simple cipher implementations for learning purposes

## Security Notes and Warnings

⚠️ **Important Security Considerations:**

- **Educational Purpose Only**: The cipher implementations are for learning and should NOT be used for actual security applications
- **XOR Cipher Warning**: The XOR implementation is extremely basic and insecure - never use for real data protection
- **Hash Algorithm Notes**: MD5 and SHA-1 are included for educational purposes but are cryptographically broken
- **Password Handling**: Be cautious when entering passwords in command line (may be visible in shell history)

## Ethical Use Guidelines

This tool is intended for:
- ✅ Learning cybersecurity concepts
- ✅ Educational demonstrations
- ✅ Understanding password security
- ✅ Exploring cryptographic principles

This tool should NOT be used for:
- ❌ Breaking into systems you don't own
- ❌ Cracking passwords without authorization
- ❌ Any illegal or unethical activities

## Examples

### Complete Workflow Example
```bash
# 1. Check your current password
python edu_security_tools.py password-check --password "password123"

# 2. Generate a stronger password
python edu_security_tools.py generate-password --length 16

# 3. Demonstrate why hashing is important
python edu_security_tools.py hash-demo --text "password123" --algorithm sha256

# 4. Learn about basic encryption
python edu_security_tools.py cipher-demo --text "Hello World" --cipher caesar --shift 5
```

## Technical Details

### Password Strength Scoring
The password analyzer uses a comprehensive scoring system:
- **Length**: 2 points for 8+ characters
- **Character Variety**: 1 point each for lowercase, uppercase, digits, symbols
- **Uniqueness**: 1 point for avoiding common passwords
- **Complexity**: 1 point for character diversity

### Security Implementation
- Uses `secrets` module for cryptographically secure random generation
- Implements proper error handling and input validation
- Follows Python security best practices

## Contributing

This is an educational tool. Suggestions for improvement are welcome, but please ensure all contributions maintain the educational focus and security best practices.

## License

MIT License

Copyright (c) 2025 Educational Security Tools

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

This tool is provided for educational purposes only. Users are responsible for ensuring their use complies with all applicable laws and regulations. The authors assume no responsibility for misuse of this software.
