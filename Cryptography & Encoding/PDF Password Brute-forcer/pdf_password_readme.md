# PDF Password Recovery Tool

A Python tool for recovering passwords from password-protected PDF files using various attack methods including dictionary attacks, brute force, and custom password lists.

## ⚠️ Important Legal and Ethical Notice

**This tool should ONLY be used on PDF files that you own or have explicit written permission to access.** Using this tool on files without proper authorization may violate local, state, or federal laws. The authors are not responsible for any misuse of this software.

**Legitimate use cases include:**
- Recovering passwords for your own PDF files
- Security testing with proper authorization
- Educational purposes in controlled environments

## Features

- **Dictionary Attack**: Test passwords from a wordlist file
- **Brute Force Attack**: Systematically try all possible combinations
- **Custom Password List**: Test a specific list of passwords
- **Multiple Character Sets**: Support for digits, letters, alphanumeric, and all printable characters
- **Progress Tracking**: Real-time progress updates with attempt counts and speed
- **Flexible Limits**: Set maximum attempts to control execution time
- **Clean Output**: Clear success/failure reporting with timing information

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Install Dependencies

```bash
pip install PyPDF2
```

### Download the Script

Save the `pdf_password_recovery.py` script to your desired location.

## Usage

### Basic Syntax

```bash
python pdf_password_recovery.py <pdf_file> [options]
```

### Dictionary Attack

Use a wordlist file to test common passwords:

```bash
python pdf_password_recovery.py document.pdf -w wordlist.txt
```

With maximum attempts limit:

```bash
python pdf_password_recovery.py document.pdf -w wordlist.txt --max-attempts 1000
```

### Brute Force Attack

Try all combinations up to a specified length:

```bash
# Brute force with digits only (0-9)
python pdf_password_recovery.py document.pdf -n 4 --charset digits

# Brute force with letters only (a-z, A-Z)
python pdf_password_recovery.py document.pdf -n 3 --charset letters

# Brute force with alphanumeric (a-z, A-Z, 0-9)
python pdf_password_recovery.py document.pdf -n 4 --charset alphanumeric

# Brute force with all printable characters
python pdf_password_recovery.py document.pdf -n 3 --charset all
```

### Custom Password List

Test specific passwords:

```bash
python pdf_password_recovery.py document.pdf -c password123 admin letmein secret
```

### Create Sample Wordlist

Generate a sample wordlist for testing:

```bash
python pdf_password_recovery.py --create-sample-wordlist
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `pdf_file` | Path to the password-protected PDF file |
| `-w, --wordlist` | Path to wordlist file for dictionary attack |
| `-n, --brute-force` | Maximum length for brute force attack |
| `-c, --custom` | Custom list of passwords to test |
| `--charset` | Character set for brute force: `digits`, `letters`, `alphanumeric`, `all` |
| `--max-attempts` | Maximum number of password attempts |
| `--create-sample-wordlist` | Create a sample wordlist file |

## Examples

### Example 1: Dictionary Attack
```bash
python pdf_password_recovery.py confidential.pdf -w rockyou.txt --max-attempts 10000
```

### Example 2: Brute Force Numeric Passwords
```bash
python pdf_password_recovery.py invoice.pdf -n 6 --charset digits
```

### Example 3: Testing Common Passwords
```bash
python pdf_password_recovery.py report.pdf -c password 123456 admin letmein welcome
```

### Example 4: Limited Brute Force
```bash
python pdf_password_recovery.py secure.pdf -n 4 --charset alphanumeric --max-attempts 50000
```

## Performance Considerations

- **Dictionary attacks** are fastest when using targeted wordlists
- **Brute force attacks** become exponentially slower with increased length and character set size
- **Character set complexity**:
  - `digits` (10 chars): Fastest
  - `letters` (52 chars): Medium
  - `alphanumeric` (62 chars): Slower
  - `all` (95 chars): Slowest

### Estimated Brute Force Times

| Length | Digits | Alphanumeric | All Characters |
|--------|--------|--------------|----------------|
| 3 chars | < 1 sec | < 1 sec | ~30 sec |
| 4 chars | < 1 sec | ~1 min | ~45 min |
| 5 chars | ~10 sec | ~1 hour | ~3 days |
| 6 chars | ~2 min | ~2.5 days | ~9 months |

*Times are approximate and depend on system performance*

## Wordlist Resources

Popular wordlist sources for dictionary attacks:
- **SecLists**: https://github.com/danielmiessler/SecLists
- **RockYou**: Common passwords from data breaches
- **Custom Lists**: Create domain-specific wordlists

## Troubleshooting

### Common Issues

1. **"PyPDF2 not found"**
   ```bash
   pip install PyPDF2
   ```

2. **"PDF file is not password protected"**
   - Verify the PDF actually requires a password
   - Some PDFs may have restrictions but no user password

3. **"Permission denied"**
   - Ensure you have read access to the PDF file
   - Check file is not open in another application

4. **Slow performance**
   - Use more targeted wordlists
   - Reduce brute force length
   - Use simpler character sets

### Getting Help

For issues or questions:
1. Check that you're using Python 3.6+
2. Verify all dependencies are installed
3. Ensure proper file permissions
4. Try with a known password first to test functionality

## Security Notes

- This tool creates no permanent modifications to PDF files
- Passwords are tested in memory and not stored
- Consider using virtual environments for dependency isolation
- Be mindful of system resources during brute force attacks

## Limitations

- Only works with user password protection (not owner passwords for restrictions)
- Performance depends on PDF encryption strength
- Very long or complex passwords may be impractical to brute force
- Some PDF encryption methods may not be supported by PyPDF2

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool.

## License

MIT License

Copyright (c) 2025

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

This software is provided for educational and legitimate recovery purposes only. Users are solely responsible for ensuring their use complies with applicable laws and regulations. The authors disclaim any responsibility for misuse of this software.
