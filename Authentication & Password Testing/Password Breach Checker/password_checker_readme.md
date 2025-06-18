# Password Breach Checker

A Python tool to check if passwords have appeared in known data breaches using the HaveIBeenPwned API. This tool prioritizes privacy by using k-anonymity - only the first 5 characters of your password's SHA-1 hash are sent to the API, ensuring your actual password never leaves your system.

## Features

- ✅ **Privacy-focused**: Uses k-anonymity to protect password privacy
- ✅ **Multiple input methods**: Single password, file input, or interactive mode
- ✅ **Rate limiting**: Configurable delays between API requests
- ✅ **Comprehensive output**: Shows breach counts and formatted results
- ✅ **Error handling**: Robust error handling for network issues and file operations
- ✅ **Command-line interface**: Easy to use with argparse
- ✅ **Cross-platform**: Works on Windows, macOS, and Linux

## How It Works

The tool uses the [HaveIBeenPwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) which implements k-anonymity:

1. Your password is hashed using SHA-1
2. Only the first 5 characters of the hash are sent to the API
3. The API returns all hash suffixes that start with those 5 characters
4. Your full hash is matched locally against the returned list
5. Your actual password never leaves your computer

## Installation

### Prerequisites

- Python 3.6 or higher
- Internet connection

### Dependencies

The script uses only standard Python libraries and one external dependency:

```bash
pip install requests
```

### Download and Setup

1. Download the `password_breach_checker.py` script
2. Make it executable (Unix/Linux/macOS):
   ```bash
   chmod +x password_breach_checker.py
   ```

## Usage

### Command Line Arguments

```
python password_breach_checker.py [options]

Required (choose one):
  --password PASSWORD, -p PASSWORD    Single password to check
  --file FILE, -f FILE               File containing passwords (one per line)
  --interactive, -i                  Run in interactive mode

Optional:
  --hide-passwords                   Hide passwords in output (show asterisks)
  --delay DELAY                      Delay between API requests in seconds (default: 0.1)
  --user-agent USER_AGENT           Custom User-Agent for API requests
  --help, -h                        Show help message
```

### Examples

#### Check a Single Password
```bash
python password_breach_checker.py --password "mypassword123"
```

Output:
```
⚠️  WARNING: Password "mypassword123" found in 2,417,804 breaches!
```

#### Check Passwords from a File
```bash
python password_breach_checker.py --file passwords.txt
```

Create a `passwords.txt` file with one password per line:
```
password123
admin
qwerty123
MySecureP@ssw0rd2024!
```

#### Interactive Mode (Recommended for Manual Testing)
```bash
python password_breach_checker.py --interactive
```

This mode hides your password input and doesn't display the actual password in results.

#### Hide Passwords in Output
```bash
python password_breach_checker.py --file passwords.txt --hide-passwords
```

#### Custom Rate Limiting
```bash
python password_breach_checker.py --file passwords.txt --delay 0.5
```

### Exit Codes

- `0`: All passwords are safe (not found in breaches)
- `1`: One or more passwords found in breaches, or an error occurred

## Security Considerations

### What This Tool Does
- ✅ Checks passwords against known data breaches
- ✅ Uses privacy-preserving k-anonymity
- ✅ Never sends your actual password over the internet
- ✅ Helps you identify compromised passwords

### What This Tool Doesn't Do
- ❌ Store or log your passwords
- ❌ Crack or guess passwords
- ❌ Perform any malicious activities
- ❌ Guarantee password security (absence from breaches doesn't mean a password is strong)

### Best Practices
1. **Only check passwords you own** or have explicit permission to check
2. **Don't use this tool on shared computers** for sensitive passwords
3. **Change any passwords** found in breaches immediately
4. **Use unique, strong passwords** for all accounts
5. **Consider using a password manager** to generate and store unique passwords

## Ethical Use

This tool is designed for legitimate security purposes:
- ✅ Checking your own passwords
- ✅ Security audits with proper authorization
- ✅ Educational purposes
- ✅ Helping others check their passwords (with permission)

**Do not use this tool to:**
- ❌ Check passwords you don't own without permission
- ❌ Attempt to compromise accounts or systems
- ❌ Violate any laws or terms of service

## API Rate Limiting

The HaveIBeenPwned API has rate limits:
- The script includes a default 0.1-second delay between requests
- For large lists, consider increasing the delay with `--delay`
- Be respectful of the free API service

## Troubleshooting

### Common Issues

**"Error querying API"**
- Check your internet connection
- The API might be temporarily unavailable
- Try again with a longer delay

**"Password file not found"**
- Verify the file path is correct
- Ensure you have read permissions for the file

**"No passwords found in file"**
- Check that your password file isn't empty
- Ensure passwords are on separate lines
- Verify file encoding (should be UTF-8)

### Debug Mode

For additional debugging information, you can modify the script to include more verbose output or run with Python's verbose flag:

```bash
python -v password_breach_checker.py --password "test"
```

## Contributing

This script is provided as-is for educational and security purposes. If you find bugs or have suggestions for improvements:

1. Test your changes thoroughly
2. Ensure they follow the same security and privacy principles
3. Document any new features clearly

## License

MIT License

Copyright (c) 2024 Password Breach Checker

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

## Acknowledgments

- [HaveIBeenPwned](https://haveibeenpwned.com/) by Troy Hunt for providing the free API
- The security community for promoting responsible password security practices

## Disclaimer

This tool is for educational and legitimate security purposes only. Users are responsible for ensuring they comply with all applicable laws and terms of service. The authors are not responsible for any misuse of this tool.

---

**Remember**: Finding that a password hasn't been breached doesn't mean it's secure. Always use strong, unique passwords and consider using a reputable password manager.