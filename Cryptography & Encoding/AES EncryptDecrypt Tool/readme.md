# AES EncryptDecrypt Tool

A secure, command-line tool for encrypting and decrypting files or text using industry-standard AES-256 encryption. This tool implements best practices for cryptographic security, including authenticated encryption, secure key derivation, and integrity verification.

## Features

- **AES-256-GCM Encryption**: Uses the Advanced Encryption Standard with 256-bit keys in Galois/Counter Mode for authenticated encryption
- **Secure Key Derivation**: Implements PBKDF2 with SHA-256 and 100,000 iterations to derive encryption keys from passwords
- **Authentication & Integrity**: Includes HMAC-SHA256 for additional authentication and integrity verification
- **Flexible Input/Output**: Supports file encryption/decryption, direct text encryption, and stdin/stdout operations
- **Secure Password Handling**: Uses `getpass` to securely prompt for passwords without echoing to the terminal
- **Comprehensive Error Handling**: Provides clear error messages and proper validation
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Security Features

- **Salt**: Uses 32-byte random salt for each encryption to prevent rainbow table attacks
- **Random IV**: Each encryption uses a unique 16-byte initialization vector
- **Authenticated Encryption**: GCM mode provides built-in authentication
- **HMAC Verification**: Additional layer of authentication using HMAC-SHA256
- **Secure Random Generation**: Uses cryptographically secure random number generation

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Install Dependencies

```bash
pip install pycryptodome
```

### Download the Script

Save the `aes_tool.py` script to your desired location and make it executable:

```bash
chmod +x aes_tool.py
```

## Usage

### Basic Commands

The tool supports two main commands: `encrypt` and `decrypt`.

#### Encrypt a File

```bash
python aes_tool.py encrypt -i input.txt -o encrypted.bin
```

#### Decrypt a File

```bash
python aes_tool.py decrypt -i encrypted.bin -o decrypted.txt
```

#### Encrypt Text Directly

```bash
python aes_tool.py encrypt -t "Hello, World!" -o message.enc
```

#### Decrypt and Display

```bash
python aes_tool.py decrypt -i message.enc
```

### Advanced Usage

#### Using Stdin/Stdout

Encrypt data from stdin:
```bash
echo "Secret message" | python aes_tool.py encrypt -o message.enc
```

Decrypt to stdout:
```bash
python aes_tool.py decrypt -i message.enc
```

Chain operations:
```bash
echo "Secret data" | python aes_tool.py encrypt | python aes_tool.py decrypt
```

#### Command Line Password (Not Recommended)

For automation purposes, you can provide the password via command line, but this is **not recommended** for security reasons:

```bash
python aes_tool.py encrypt -i file.txt -o file.enc -p mypassword
```

**Warning**: Passwords provided via command line may be visible in process lists and shell history.

## Command Reference

### Global Options

- `-h, --help`: Show help message and exit

### Encrypt Command

```
python aes_tool.py encrypt [options]
```

**Required (choose one):**
- `-i, --input FILE`: Input file to encrypt
- `-t, --text TEXT`: Text string to encrypt

**Optional:**
- `-o, --output FILE`: Output file for encrypted data (default: stdout as base64)
- `-p, --password PASS`: Encryption password (insecure, not recommended)

### Decrypt Command

```
python aes_tool.py decrypt [options]
```

**Optional:**
- `-i, --input FILE`: Input file to decrypt (default: stdin as base64)
- `-o, --output FILE`: Output file for decrypted data (default: stdout)
- `-p, --password PASS`: Decryption password (insecure, not recommended)

## Examples

### Example 1: Secure Document Encryption

```bash
# Encrypt a document
python aes_tool.py encrypt -i confidential.pdf -o confidential.pdf.enc
Enter encryption password: [password hidden]
Encryption complete. Output saved to: confidential.pdf.enc

# Decrypt the document
python aes_tool.py decrypt -i confidential.pdf.enc -o confidential_decrypted.pdf
Enter decryption password: [password hidden]
Decryption complete. Output saved to: confidential_decrypted.pdf
```

### Example 2: Text Message Encryption

```bash
# Encrypt a message
python aes_tool.py encrypt -t "This is a secret message" -o secret.enc
Enter encryption password: [password hidden]
Encryption complete. Output saved to: secret.enc

# Decrypt and view the message
python aes_tool.py decrypt -i secret.enc
Enter decryption password: [password hidden]
Decrypted text:
This is a secret message
```

### Example 3: Backup Encryption Workflow

```bash
# Create and encrypt a backup
tar -czf backup.tar.gz /important/files/
python aes_tool.py encrypt -i backup.tar.gz -o backup.tar.gz.enc
rm backup.tar.gz  # Remove unencrypted backup

# Later, decrypt and restore
python aes_tool.py decrypt -i backup.tar.gz.enc -o backup.tar.gz
tar -xzf backup.tar.gz
```

## File Format

The encrypted file format includes all necessary components for secure decryption:

```
[32-byte Salt][16-byte IV][16-byte GCM Tag][Encrypted Data][32-byte HMAC]
```

- **Salt**: Used for key derivation (prevents rainbow table attacks)
- **IV**: Initialization vector for AES-GCM (ensures unique encryption)
- **GCM Tag**: Authentication tag from GCM mode
- **Encrypted Data**: The actual encrypted content
- **HMAC**: Hash-based message authentication code for integrity verification

## Security Considerations

### Strengths

- Uses AES-256, the industry standard for symmetric encryption
- Implements authenticated encryption (AES-GCM + HMAC)
- Secure key derivation with PBKDF2
- Protects against common attacks (rainbow tables, bit-flipping, etc.)
- Cryptographically secure random number generation

### Best Practices

1. **Strong Passwords**: Use long, complex passwords with mixed character types
2. **Password Management**: Store passwords securely, never in plain text
3. **Secure Deletion**: Securely wipe original files after encryption
4. **Backup Strategy**: Maintain secure backups of encrypted files
5. **Regular Updates**: Keep the tool and dependencies updated

### Limitations

- **Password Security**: The security depends entirely on password strength
- **Key Management**: No built-in key management system
- **Memory Security**: Sensitive data may remain in memory temporarily
- **Side-Channel Attacks**: Not protected against advanced side-channel attacks

## Error Handling

The tool provides comprehensive error handling for common scenarios:

- **File Not Found**: Clear message when input files don't exist
- **Permission Errors**: Helpful messages for file access issues
- **Corruption Detection**: HMAC verification detects data corruption
- **Wrong Password**: Clear indication of authentication failure
- **Invalid Format**: Detection of malformed encrypted data

## Troubleshooting

### Common Issues

**"ModuleNotFoundError: No module named 'Crypto'"**
- Solution: Install pycryptodome with `pip install pycryptodome`

**"Permission denied" errors**
- Solution: Check file permissions and directory access rights

**"HMAC verification failed"**
- This usually indicates:
  - Wrong password
  - Corrupted encrypted file
  - File was modified after encryption

**"Encrypted data is too short to be valid"**
- The encrypted file may be corrupted or not created by this tool

### Getting Help

If you encounter issues:

1. Check that all dependencies are installed correctly
2. Verify file permissions and paths
3. Ensure you're using the correct password
4. Check that encrypted files haven't been modified

## License

This project is licensed under the MIT License - see below for details:

```
MIT License

Copyright (c) 2025 AES EncryptDecrypt Tool

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
```

## Contributing

Contributions are welcome! If you find bugs or have suggestions for improvements:

1. Ensure any security-related issues are reported responsibly
2. Test thoroughly before submitting changes
3. Follow Python coding standards (PEP 8)
4. Include appropriate documentation and comments

## Disclaimer

This tool is provided for legitimate encryption needs. Users are responsible for:

- Complying with applicable laws and regulations
- Using strong passwords and secure practices
- Maintaining secure backups of important data
- Understanding the security implications of their usage

The authors assume no responsibility for data loss, security breaches, or misuse of this tool.
